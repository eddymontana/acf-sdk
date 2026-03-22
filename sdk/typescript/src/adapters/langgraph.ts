/**
 * Optional FirewallNode adapter for LangGraph.js.
 * Wraps a Firewall instance as a LangGraph node. Fires onPrompt or onContext
 * depending on configuration. Throws on BLOCK decisions.
 */
