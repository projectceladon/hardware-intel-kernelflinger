/*
function needed for compiling borningssl on Android O
*/
long syscall(long __number, ...){return 0;};
void perror(const char* __msg){Print("error message :%s",__msg);};
