#include "ScStdio.h"
#include <iostream>

using namespace std;
int main(void) {
	 cout << ScStdio::MalCode << endl;
	 ScStdio::WriteShellcodeToDisk();	

	 ScStdio::Test<const char*>("Hello World!");
	 cin.get();

}