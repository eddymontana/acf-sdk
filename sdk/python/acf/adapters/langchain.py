"""
FirewallCallbackHandler — optional LangChain callback wrapper.
Hooks into LangChain's callback system to intercept tool calls (on_tool_start)
and LLM inputs (on_llm_start). Raises ToolException on BLOCK decisions.

Import is guarded: importing this module without langchain installed raises
ImportError with a helpful message (langchain is not a required dependency).
"""
