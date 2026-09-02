package com.contrastsecurity.runtimeanalyst;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
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

    /**
     * For entries in connectedApplications that are themselves other Contrast applications
     * (as opposed to a server/library cluster), maps the connected application's
     * contrast-graph display name to its applicationId. The graph's display name for an
     * application does not always match that application's "applicationName" as reported by
     * the /observations endpoint, so consumers that need to resolve a connection back to an
     * application they already know about (e.g. to link a Blueprint flow to an existing asset
     * instead of creating a spurious duplicate) should resolve via this map by id first, and
     * only fall back to matching on the name string.
     */
    public Map<String, String> connectedApplicationIds = new HashMap<>();
}
