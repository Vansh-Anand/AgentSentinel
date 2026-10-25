"use strict";

// Flowise 3.1.4 loads this node from flowise-components/dist/nodes.
// It calls one pinned loopback service outside Flowise's user-code NodeVM.
// No model-supplied URL, port, credential, or HTTP method is accepted.
const { createHash, randomUUID } = require('node:crypto');
const { DynamicStructuredTool } = require('@langchain/core/tools');
const { z } = require('zod/v3');
const { getBaseClasses, getVars } = require('../../../src/utils');

const TERMINAL = new Set(['COMPLETED', 'BLOCKED', 'STOPPED', 'ERROR', 'CANCELLED']);
const DEFAULT_URL = 'http://127.0.0.1:8010';

function gatewayUrl() {
  const url = process.env.AGENTSENTINEL_FLOWISE_GATEWAY_URL || DEFAULT_URL;
  if (!/^http:\/\/127\.0\.0\.1:\d{1,5}$/.test(url)) {
    throw new Error('AgentSentinel gateway must be a numeric 127.0.0.1 HTTP endpoint');
  }
  return url;
}

async function request(url, headers, method, body) {
  const response = await fetch(url, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body),
    redirect: 'error', signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) throw new Error(`AgentSentinel gateway HTTP ${response.status}`);
  return response.json();
}

class AgentSentinelGateway {
  constructor() {
    this.label = 'AgentSentinel Gateway';
    this.name = 'agentSentinelGateway';
    this.version = 1;
    this.type = 'AgentSentinelGateway';
    this.icon = 'gateway.svg';
    this.category = 'Tools';
    this.description = 'Propose a synthetic action to the AgentSentinel policy gateway.';
    this.baseClasses = [this.type, 'Tool', ...getBaseClasses(DynamicStructuredTool)];
  }

  async init(nodeData, _, options) {
    const variables = await getVars(options.appDataSource, options.databaseEntities, nodeData, options);
    const item = variables.find(value => value.name === 'agentSentinelCapability');
    const capability = item?.type === 'runtime' ? process.env.agentSentinelCapability : item?.value;
    if (typeof capability !== 'string' || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(capability)) {
      throw new Error('Set a fresh agentSentinelCapability Flowise variable before running this chatflow');
    }
    const base = gatewayUrl();
    return new DynamicStructuredTool({
      name: 'agentsentinel_action',
      description: 'The only action tool. Propose read_file, search_documents, calculate, create_report, create_ticket, execute_command, or http_post. AgentSentinel decides whether the action is permitted and returns a signed-evidence result. Never describe a tool error as a gateway denial.',
      schema: z.object({
        tool: z.string().min(1).describe('Proposed action name'),
        arguments: z.string().describe('JSON object string of action arguments, e.g. {"path":"README.md"}')
      }),
      func: async ({ tool, arguments: raw }) => {
        try {
          let args;
          try { args = JSON.parse(raw); } catch { throw new Error('arguments must be a JSON object string'); }
          if (!args || Array.isArray(args) || typeof args !== 'object') {
            throw new Error('arguments must be a JSON object');
          }
          const headers = { 'X-Lab-Capability': capability, 'Content-Type': 'application/json' };
          const material = JSON.stringify({ tool, args });
          const id = `flowise-${createHash('sha256').update(material).digest('hex').slice(0, 24)}-${randomUUID().slice(0, 8)}`;
          const admission = await request(`${base}/api/lab/adapter/integration/action`, headers, 'POST', {
            tool, arguments: args, client_request_id: id
          });
          if (!/^[0-9a-f-]{36}$/i.test(String(admission.run_id || ''))) {
            throw new Error('AgentSentinel returned no valid run ID');
          }
          let run;
          for (let attempt = 0; attempt < 60; attempt++) {
            run = await request(`${base}/api/lab/adapter/integration/runs/${admission.run_id}`, headers, 'GET');
            if (TERMINAL.has(run.status)) break;
            await new Promise(resolve => setTimeout(resolve, 500));
          }
          if (!TERMINAL.has(run?.status)) throw new Error(`Run ${admission.run_id} did not finish within 30 seconds`);
          const action = run.result?.steps?.find(step => step.request_id?.endsWith(':1')) || run.result?.steps?.at(-1);
          return JSON.stringify({
            run_id: admission.run_id, request_id: action?.request_id || null,
            status: run.status, decision: action?.decision || null,
            reason: run.result?.reason || null,
            executor_invoked: action?.executor_invoked === true,
            output: action?.decision === 'ALLOW' && action?.completed === true ? run.result?.adapter_output || '' : null,
            signed_evidence_valid: run.result?.verification?.valid === true
          });
        } catch (error) {
          return JSON.stringify({ integration_error: String(error.message || error), gateway_decision: null });
        }
      }
    });
  }
}

module.exports = { nodeClass: AgentSentinelGateway };
