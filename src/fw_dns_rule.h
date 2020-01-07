#ifndef	__FW_DNS_RULE_H__
#define	__FW_DNS_RULE_H__

#define	MIN(a, b) ((a>b) ? b: a)

#define	MAX_TABLE_NAME_LEN	32

struct _dns_str2idx
{
	int index;
	int len;
	char *type;
};

typedef struct _cb_rule
{
	int record_id;
	int record_num;
	int is_valid;
	char record_type[128];
	char record_name[MAX_TABLE_NAME_LEN];
	void **record_values;
}cb_rule_t;

typedef struct _fw_dns_rule
{
	int table_records_id;
	char table_records_name[MAX_TABLE_NAME_LEN];
}fw_dns_rule_t;


int fw_dns_type2index(char *type);
int fw_dns_rule_init(const char *conffile, void *logger);
int get_cheat_opt(int record_id, int select_num, int ttl, int atype, cheat_pkt_opt_t* cheat_opt, int cheat_opt_num);
	
#endif
