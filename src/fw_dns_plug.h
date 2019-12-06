#ifndef	__FW_DNS_PLUG_H__
#define	__FW_DNS_PLUG_H__

#include "fw_dns_rule.h"

#define	MAX_ANSWER_RECORDS_NUM	32

struct _fw_dns_plug
{
	int table_qname_id;
	char table_qname[MAX_TABLE_NAME_LEN];
	void *logger;
};

#endif