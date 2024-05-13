#pragma once
typedef struct sReadWrite {
	INT32 security;
	INT32 process_id;
	ULONGLONG address;
	ULONGLONG buffer;
	ULONGLONG size;
	BOOLEAN write;
} rw, * prw; // yh too tired rn to change its like 1am

typedef struct sBaseAddress {
	INT32 security;
	INT32 process_id;
	ULONGLONG* address;
} ba, * pba; // same shit here

typedef struct sGuardedRegion {
	INT32 security;
	ULONGLONG* address;
} ga, * pga; // yup! here too lol do that urself