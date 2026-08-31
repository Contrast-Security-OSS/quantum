package com.contrastsecurity.quantum;

import java.util.HashSet;
import java.util.Set;

/**
 * Application-level architecture/connection info from the Contrast graph
 * (contrast-graph API): language, posture, criticality, and what the
 * application is connected to.
 */
public class AppGraphInfo {
    /** The contrast-graph node id (e.g. "-1339855761") - used as the "detailsId" query
     *  param for a deep link to this application's page in the Contrast Explorer UI. */
    public String nodeId;
    public String language;
    public Double postureScore;
    public String postureSeverity;
    public Integer criticality;
    public Integer openIssuesTotal;
    public int serverCount;
    public int libraryCount;
    public Set<String> connectedApplications = new HashSet<>();
}
