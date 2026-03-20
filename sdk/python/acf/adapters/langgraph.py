"""
FirewallNode — optional LangGraph node wrapper.
Wraps a Firewall instance as a LangGraph node that can be inserted into a
StateGraph. Fires on_prompt or on_context depending on configuration, and
raises NodeInterrupt on BLOCK decisions.

Import is guarded: importing this module without langgraph installed raises
ImportError with a helpful message (langgraph is not a required dependency).
"""
