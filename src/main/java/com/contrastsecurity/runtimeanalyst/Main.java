package com.contrastsecurity.runtimeanalyst;

import java.util.Arrays;

/**
 * Single CLI entry point for the jar. Dispatches to CBOMGenerator or AIBOMGenerator
 * based on the first argument.
 *
 * Usage:
 *   java -jar runtime-analyst.jar cbom [options]    # Cryptography Bill of Materials
 *   java -jar runtime-analyst.jar aibom [options]   # AI/LLM usage Bill of Materials
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
            case "auth":
                AuthCommand.main(rest);
                break;
            case "cbom":
                CBOMGenerator.main(rest);
                break;
            case "aibom":
                AIBOMGenerator.main(rest);
                break;
            case "cbom-advisor":
                QuantumAdvisor.main(rest);
                break;
            case "aibom-advisor":
                AIAdvisor.main(rest);
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
        System.out.println("\nRuntime Analyst - Contrast Security Bill of Materials generator");
        System.out.println("\nUsage:");
        System.out.println("  java -jar runtime-analyst.jar auth [options]              Connect to Contrast and generate contrast.properties");
        System.out.println("  java -jar runtime-analyst.jar cbom [options]              Generate a Cryptography Bill of Materials");
        System.out.println("  java -jar runtime-analyst.jar aibom [options]             Generate an AI/LLM usage Bill of Materials");
        System.out.println("  java -jar runtime-analyst.jar cbom-advisor <cbom.json>    Re-run the Quantum Advisor against an existing CBOM");
        System.out.println("  java -jar runtime-analyst.jar aibom-advisor <aibom.json>  Re-run the AI Advisor against an existing AI-BOM");
        System.out.println("\n`cbom --analyze` / `aibom --analyze` already run the matching advisor automatically after generation -");
        System.out.println("the standalone cbom-advisor/aibom-advisor commands are for re-running the advisor without regenerating the BOM.");
        System.out.println("\nRun with -h after a subcommand for its options, e.g.:");
        System.out.println("  java -jar runtime-analyst.jar cbom -h");
        System.out.println("  java -jar runtime-analyst.jar aibom -h");
    }
}
