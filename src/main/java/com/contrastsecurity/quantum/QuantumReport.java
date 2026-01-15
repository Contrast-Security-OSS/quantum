package com.contrastsecurity.quantum;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.LineIterator;

public class QuantumReport {

    static enum State {
        DEFAULT, INFINDING, INSTACK
    }
    
    public final static String STACK = "DEBUG - Stack Trace -";
    public final static String FRAME = "DEBUG - \tat ";

    public final static String ROUTE = "DEBUG - Route - ";

    public final static String CRYPTOAUDIT = "DEBUG - Crypto Audit: ";
    public final static String CRYPTOCLASS = "DEBUG - Crypto Class - ";
    public final static String CRYPTOFUNCTION = "DEBUG - Crypto Function - ";
    public final static String CRYPTOLINE = "DEBUG - Crypto Line - ";

    public final static String HASHAUDIT = "DEBUG - Hash Audit: ";
    public final static String HASHCLASS = "DEBUG - Hash Class - ";
    public final static String HASHFUNCTION = "DEBUG - Hash Function - ";
    public final static String HASHLINE = "DEBUG - Hash Line - ";

    public final static String CALLERCLASS = "DEBUG - Likely Caller Class - ";
    public final static String CALLERFUNCTION = "DEBUG - Likely Caller Function - ";
    public final static String CALLERLINE = "DEBUG - Likely Caller Line - ";
    public final static String ALGORITHM = "DEBUG - Algorithm - ";
    
    private static State state = State.DEFAULT;
    private static Finding f = new Finding();

    private static Set<Finding> findings = new HashSet<Finding>();
    public static void main(String[] args) {

        System.out.println( "\nContrast Cryptographic Algorithm Inventory" );

        // read log
        File log = null;
        try {
            if ( args.length != 1 ) {
                throw new Exception( "Log file missing" );
            }
            log = new File( args[0] );
        } catch ( Exception e ) {
            System.err.println( "  Usage: java -jar quantum.jar contrast.log" );
            System.exit( -1 );
        }
        System.out.println( "  Loading data from " + log );

        // find quantum reports
        try {
            System.out.print( "  Searching");
            LineIterator i = FileUtils.lineIterator(log);
            while ( i.hasNext() ) {
                String line = i.next();
                process( line );
            }
            System.out.println();
        } catch( IOException e ) {
            System.err.println( "  Error reading log file " + log );
        }

        // write out findings to csv
        System.out.println( "  Found " + findings.size() + " unique instances of cryptographic algorithm use" );
        saveReport( "Quantum-" + log.getName() + ".csv" );
        System.out.println( "  Done" );
    }

    private static void process(String line) {
        switch( state ) {
            case DEFAULT:
                if ( line.contains( CRYPTOAUDIT ) || line.contains( HASHAUDIT ) ) {
                    state = State.INFINDING;
                }
                break;

            case INFINDING:
                if ( line.contains(ROUTE) ) f.route = chop(ROUTE, line);
                else if ( line.contains(CRYPTOCLASS) ) f.cryptoClass = chop(CRYPTOCLASS, line);
                else if ( line.contains(CRYPTOFUNCTION) ) f.cryptoFunction = chop(CRYPTOFUNCTION, line);
                else if ( line.contains(CRYPTOLINE) ) f.cryptoLine = chop(CRYPTOLINE, line);
                else if ( line.contains(HASHCLASS) ) f.cryptoClass = chop(HASHCLASS, line);
                else if ( line.contains(HASHFUNCTION) ) f.cryptoFunction = chop(HASHFUNCTION, line);
                else if ( line.contains(HASHLINE) ) f.cryptoLine = chop(HASHLINE, line);
                else if ( line.contains(CALLERCLASS) ) f.callerClass = chop(CALLERCLASS, line);
                else if ( line.contains(CALLERFUNCTION) ) f.callerFunction = chop(CALLERFUNCTION, line);
                else if ( line.contains(CALLERLINE) ) f.callerLine = chop(CALLERLINE, line);
                else if ( line.contains(ALGORITHM) ) f.algorithm = chop(ALGORITHM, line);
                else state = State.INSTACK;
                break;

            case INSTACK:
                if ( line.contains( FRAME ) ) {
                    f.trace.add( chop( FRAME, line ) );
                }
                else {
                    state = State.DEFAULT;
                    findings.add( f );
                    f = new Finding();
                    System.out.print('.');
                }
                break;
        }
    }


    private static String chop(String prefix, String line) {
        int idx = line.indexOf( prefix );
        return line.substring( idx + prefix.length() );
    }
        
    private static void saveReport(String filename) {
        File file = new File( filename );
        System.out.print( "  Saving " + file.getName() );
        String[] HEADERS = { "route", "algorithm", "cryptoClass", "cryptoFunction", "cryptoLine", "callerClass", "callerFunction", "callerLine", "stacktrace" };
        CSVFormat csvFormat = CSVFormat.DEFAULT.builder()
            .setHeader(HEADERS)
            .get();
    
        CSVPrinter printer = null;
        try {
            FileWriter fw = new FileWriter( file );
            printer = new CSVPrinter(fw, csvFormat);  
            for ( Finding f : findings ) {
                System.out.print('.');
                String stacktrace = f.trace.toString().replace( ',','\n');
                stacktrace = stacktrace.substring(1,stacktrace.length()-1 );
                printer.printRecord( f.route, f.algorithm, f.cryptoClass, f.cryptoFunction, f.cryptoLine, f.callerClass, f.callerFunction, f.callerLine, stacktrace );
                // TBD: temporary self parsing stack instead of agent
                // Finding.Frame frame0 = f.parseFrame( f.trace.get(0) );
                // Finding.Frame frame1 = f.parseFrame( f.trace.get(1) );
                // printer.printRecord( f.route, f.algorithm, frame0.clazz, frame0.method, frame0.line, frame1.clazz, frame1.method, frame1.line, stacktrace );
            }
            System.out.println();
            fw.close();
        } catch( Exception e ) {
            System.err.println( "Error writing Quantum CSV file: " + file.getName() );
        } finally {
            try {
                printer.close();
            } catch( Exception e ) {}
        }

    
    }

}

