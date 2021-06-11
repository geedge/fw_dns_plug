#ifndef	__FW_DNS_PLUG_H__
#define	__FW_DNS_PLUG_H__

#include "fw_dns_rule.h"

#define	MAX_ANSWER_RECORDS_NUM	32

struct fw_dns_plug
{
	int mode;
	int level;
	int table_qname_id;
	char table_qname[MAX_TABLE_NAME_LEN];
	char s_mode[MAX_TABLE_NAME_LEN];
	char log_path[MAX_TABLE_NAME_LEN*2];
	void *logger;
};

#endif