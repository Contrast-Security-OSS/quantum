package com.contrastsecurity.bomsquad;

import java.util.ArrayList;
import java.util.List;

public class Finding {
    public String route = null;
    public String cryptoClass = null;
    public String cryptoFunction = null;
    public String cryptoLine = null;
    public String callerClass = null;
    public String callerFunction = null;
    public String callerLine = null;
    public String algorithm = null;
    public List<String> trace = new ArrayList<String>();

    
    @Override
    public String toString() {
        String stacktrace = trace.toString().replace( ',','\n');
        return "Finding [route=" + route + ", cryptoClass=" + cryptoClass + ", cryptoFunction=" + cryptoFunction
                + ", cryptoLine=" + cryptoLine + ", callerClass=" + callerClass + ", callerFunction=" + callerFunction
                + ", callerLine=" + callerLine + ", algorithm=" + algorithm + ", trace=" + stacktrace + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((route == null) ? 0 : route.hashCode());
        result = prime * result + ((cryptoClass == null) ? 0 : cryptoClass.hashCode());
        result = prime * result + ((cryptoFunction == null) ? 0 : cryptoFunction.hashCode());
        result = prime * result + ((cryptoLine == null) ? 0 : cryptoLine.hashCode());
        result = prime * result + ((callerClass == null) ? 0 : callerClass.hashCode());
        result = prime * result + ((callerFunction == null) ? 0 : callerFunction.hashCode());
        result = prime * result + ((callerLine == null) ? 0 : callerLine.hashCode());
        result = prime * result + ((algorithm == null) ? 0 : algorithm.hashCode());
        result = prime * result + ((trace == null) ? 0 : trace.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Finding other = (Finding) obj;
        if (route == null) {
            if (other.route != null)
                return false;
        } else if (!route.equals(other.route))
            return false;
        if (cryptoClass == null) {
            if (other.cryptoClass != null)
                return false;
        } else if (!cryptoClass.equals(other.cryptoClass))
            return false;
        if (cryptoFunction == null) {
            if (other.cryptoFunction != null)
                return false;
        } else if (!cryptoFunction.equals(other.cryptoFunction))
            return false;
        if (cryptoLine == null) {
            if (other.cryptoLine != null)
                return false;
        } else if (!cryptoLine.equals(other.cryptoLine))
            return false;
        if (callerClass == null) {
            if (other.callerClass != null)
                return false;
        } else if (!callerClass.equals(other.callerClass))
            return false;
        if (callerFunction == null) {
            if (other.callerFunction != null)
                return false;
        } else if (!callerFunction.equals(other.callerFunction))
            return false;
        if (callerLine == null) {
            if (other.callerLine != null)
                return false;
        } else if (!callerLine.equals(other.callerLine))
            return false;
        if (algorithm == null) {
            if (other.algorithm != null)
                return false;
        } else if (!algorithm.equals(other.algorithm))
            return false;
        if (trace == null) {
            if (other.trace != null)
                return false;
        } else if (!trace.equals(other.trace))
            return false;
        return true;
    }

    public class Frame {
        String clazz = null;
        String method = null;
        String line = null;
        public String toString() {
            return( clazz + "." + method + "(" + line + ")" );
        }
    }

    public Frame parseFrame( String frame ) {
        Frame f = new Frame();
        int idx = frame.indexOf( '(' );
        String full = frame.substring( 0, idx );
        idx = full.lastIndexOf( '.' );
        f.clazz = full.substring( 0, idx );
        f.method = full.substring( idx + 1 );
        idx = frame.indexOf( ":" );
        if ( idx != -1 ) {
            f.line = frame.substring( idx + 1, frame.length() -1 );
        } else {
            f.line = "-1";
        }
        return f;
    }
    
}
