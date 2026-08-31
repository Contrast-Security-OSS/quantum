package com.contrastsecurity.quantum;

import java.util.Arrays;

/**
 * Single CLI entry point for the jar. Dispatches to CBOMGenerator or AIBOMGenerator
 * based on the first argument.
 *
 * Usage:
 *   java -jar quantum.jar cbom [options]    # Cryptography Bill of Materials
 *   java -jar quantum.jar aibom [options]   # AI/LLM usage Bill of Materials
 */
public class Main {

    public static void main(String[] args) {
        if (args.length == 0) {
            printUsage();
            System.exit(1);
        }

        String subcommand = args[0];
        String[] rest = Arrays.copyOfRange(args, 1, args.length);

        switch (subcommand) {
            case "cbom":
                CBOMGenerator.main(rest);
                break;
            case "aibom":
                AIBOMGenerator.main(rest);
                break;
            case "--help":
            case "-h":
                printUsage();
                break;
            default:
                System.err.println("Unknown command: " + subcommand);
                printUsage();
                System.exit(1);
        }
    }

    private static void printUsage() {
        System.out.println("\nQuantum - Contrast Security Bill of Materials generator");
        System.out.println("\nUsage:");
        System.out.println("  java -jar quantum.jar cbom [options]     Generate a Cryptography Bill of Materials");
        System.out.println("  java -jar quantum.jar aibom [options]    Generate an AI/LLM usage Bill of Materials");
        System.out.println("\nRun with -h after a subcommand for its options, e.g.:");
        System.out.println("  java -jar quantum.jar cbom -h");
        System.out.println("  java -jar quantum.jar aibom -h");
    }
}
