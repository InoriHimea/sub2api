package com.mellivora.bamboo.isolation.proof;

import com.atlassian.bamboo.buildqueue.AgentAssignment;
import com.atlassian.bamboo.buildqueue.AgentAssignment.ExecutableType;
import com.atlassian.bamboo.buildqueue.AgentAssignment.ExecutorType;
import com.atlassian.bamboo.buildqueue.manager.AgentAssignmentMap;
import com.atlassian.bamboo.buildqueue.manager.AgentAssignmentMapImpl;
import com.atlassian.bamboo.buildqueue.manager.AgentAssignmentService.AgentAssignmentExecutable;
import com.atlassian.bamboo.buildqueue.manager.AgentAssignmentService.AgentAssignmentExecutor;
import java.lang.reflect.Proxy;
import java.util.List;

/** Executes native assignment checks; synthetic assignment rows are the persistence boundary. */
public final class NativeAssignmentSmoke {
    private static int cases;

    private static AgentAssignment row(long rowId, long agentId, long environmentId) {
        return (AgentAssignment) Proxy.newProxyInstance(AgentAssignment.class.getClassLoader(),
                new Class<?>[] { AgentAssignment.class }, (proxy, method, args) -> switch (method.getName()) {
                    case "getId" -> rowId;
                    case "getExecutorId" -> agentId;
                    case "getExecutorType" -> ExecutorType.AGENT;
                    case "getExecutableId" -> environmentId;
                    case "getExecutableType" -> ExecutableType.ENVIRONMENT;
                    case "hashCode" -> Long.hashCode(rowId);
                    case "equals" -> proxy == args[0];
                    case "toString" -> "SyntheticAssignment";
                    default -> throw new AssertionError("Unexpected persistence method");
                });
    }

    private static AgentAssignmentExecutable environment(long id, long projectId) {
        // Supplying the real native group identity avoids any fake environment-cache implementation.
        return new AgentAssignmentExecutable(ExecutableType.ENVIRONMENT, Long.valueOf(projectId), id);
    }

    private static void check(AgentAssignmentMap map, AgentAssignmentExecutable executable,
                              long agentId, boolean allowed, String label) {
        var decision = map.checkAssignmentRequirements(List.of(executable),
                List.of(new AgentAssignmentExecutor(ExecutorType.AGENT, agentId)));
        if (decision.isCanExecute() != allowed) throw new AssertionError(label + ": " + decision);
        cases++;
    }

    public static void main(String[] args) {
        var own = environment(1001, 3001);
        var foreign = environment(1002, 3002);
        AgentAssignmentMap dedicated = new AgentAssignmentMapImpl(List.of(row(9001, 42, 1001)), null, null);
        check(dedicated, own, 42, true, "dedicated target accepts own executable");
        check(dedicated, foreign, 42, false, "exclusive target rejects unassigned foreign executable");
        check(dedicated, own, 7, false, "other agent rejects target-dedicated executable");
        check(dedicated, foreign, 7, true, "unrelated agent keeps ordinary eligibility");

        AgentAssignmentMap twoTargets = new AgentAssignmentMapImpl(
                List.of(row(9001, 42, 1001), row(9002, 7, 1002)), null, null);
        check(twoTargets, foreign, 42, false, "target rejects foreign executable dedicated elsewhere");
        check(twoTargets, foreign, 7, true, "foreign owner keeps its own executable");

        // These are counterexamples, not security passes: client activation must veto a new id,
        // and operator attestation must bind the complete assignment state before release.
        check(dedicated, foreign, 43, true, "new registration id has no old exclusivity");
        AgentAssignmentMap deleted = new AgentAssignmentMapImpl(List.of(), null, null);
        check(deleted, foreign, 42, true, "removed assignment invalidates exclusivity");
        System.out.println("{\"native_assignment_cases\":" + cases
                + ",\"native_map\":\"AgentAssignmentMapImpl\",\"scope\":\"environment_dispatch\","
                + "\"new_id_and_assignment_loss_counterexamples_observed\":true}");
    }
}
