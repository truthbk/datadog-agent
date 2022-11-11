#ifndef DATADOG_AGENT_VRL_BRIDGE_H_INCLUDED
#define DATADOG_AGENT_VRL_BRIDGE_H_INCLUDED

char* run_vrl_c(char* str, void* program);
void* compile_vrl_c(char* str);

#endif