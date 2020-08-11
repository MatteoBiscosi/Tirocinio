#include <nt.h>
#include <cstdio>
#include <iostream>


void ntplCall(NtConfigStream_t& hCfgStream, const char* str)
{
  std::cout << str << std::endl;

  NtNtplInfo_t ntplInfo;
  int status = NT_NTPL(hCfgStream, str, &ntplInfo, NT_NTPL_PARSER_VALIDATE_NORMAL);
  
}


int main(int argc, char *argv[]) 
{

	NtConfigStream_t hCfgStream;		
	int status = NT_ConfigOpen(&hCfgStream, "Learn_example_config");

  // Deletion of filters and macros, and clear FPGA flow tables.
  //   ntplCall(hCfgStream, "Delete = All");
  //
  //     // KeyType Command for IPv4 and IPv6
  //       // In this example swapable field values are chosen, denoted by sw_.
        ntplCall(hCfgStream, "KeyType[Name=kt4] = {sw_32_32,   sw_16_16}");
        ntplCall(hCfgStream, "KeyType[Name=kt6] = {sw_128_128, sw_16_16}");
  //           

	return 0;
}
