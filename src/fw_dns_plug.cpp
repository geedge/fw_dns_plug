#include <stdio.h>
#include <arpa/inet.h>

#include <MESA/stream.h>
#include <MESA/dns.h>
#include <MESA/cJSON.h>
#include <MESA_prof_load.h>
#include <MESA/Maat_rule.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_rule.h"
#include "tsg_label.h"
#include "tsg_send_log.h"
#include "tsg_statistic.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define GIT_VERSION_CATTER(v) __attribute__((__used__)) const char * GIT_VERSION_##v = NULL
#define GIT_VERSION_EXPEND(v) GIT_VERSION_CATTER(v)

/* VERSION TAG */
#ifdef GIT_VERSION
GIT_VERSION_EXPEND(GIT_VERSION);
#else
static __attribute__((__used__)) const char * GIT_VERSION_UNKNOWN = NULL;
#endif
#undef GIT_VERSION_CATTER
#undef GIT_VERSION_EXPEND

#ifdef __cplusplus
}
#endif

#define	MAX_TABLE_NAME_LEN	256
struct fw_dns_plug
{
	int level;
	int table_qname_id;
	char table_qname[MAX_TABLE_NAME_LEN];
	char log_path[MAX_TABLE_NAME_LEN*2];
	void *logger;
};

char FW_DNS_PLUG_VERSION_20210607=0;
struct fw_dns_plug g_fw_dns_plug_info;
char *g_fw_dns_conffile=(char *)"tsgconf/main.conf";

static int fw_dns_send_log(struct streaminfo *a_stream, dns_info_t *dns_info, struct Maat_rule_t *result, int result_num, int thread_seq)
{
	int i=0,cname_flag=0;
	dns_rr_t *rr=NULL;
	tsg_log_t log_msg;
	int dns_sec=1;
	struct TLD_handle_t *handle=NULL;
	char *cname=NULL,*rr_buf=NULL;
	
	handle=TLD_create(thread_seq);
	
	TLD_append(handle, (char *)"dns_qr", (void *)(long)dns_info->hdr_info.qr, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_aa", (void *)(long)dns_info->hdr_info.aa, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_message_id", (void *)(long)dns_info->hdr_info.id, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_opcode", (void *)(long)dns_info->hdr_info.opcode, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_ra", (void *)(long)dns_info->hdr_info.ra, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_rcode", (void *)(long)dns_info->hdr_info.rcode, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_rd", (void *)(long)dns_info->hdr_info.rd, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_tc", (void *)(long)dns_info->hdr_info.tc, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_qdcount", (void *)(long)dns_info->hdr_info.qdcount, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_ancount", (void *)(long)dns_info->hdr_info.ancount, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_nscount", (void *)(long)dns_info->hdr_info.aucount, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"dns_arcount", (void *)(long)dns_info->hdr_info.adcount, TLD_TYPE_LONG);

	if((strlen((char *)dns_info->query_question.qname)) >0)
	{
		TLD_append(handle, (char *)"dns_qname", (void *)dns_info->query_question.qname, TLD_TYPE_STRING);		
		TLD_append(handle, (char *)"dns_qtype", (void *)(long)dns_info->query_question.qtype, TLD_TYPE_LONG);		
		TLD_append(handle, (char *)"dns_qclass", (void *)(long)dns_info->query_question.qclass, TLD_TYPE_LONG);
	}

	cJSON *item=NULL;
	cJSON *cname_array=cJSON_CreateArray();
	for(i=0; i<dns_info->rr_count && dns_info->rr != NULL; i++)
	{
		rr = &dns_info->rr[i];
		if(rr!=NULL && rr->type==DNS_TYPE_CNAME)
		{
			if(rr->rdata.cname != NULL)
			{
				item=cJSON_CreateString((const char *)rr->rdata.cname);
				cJSON_AddItemToArray(cname_array, item);
				cname_flag=1;
			}
		}
	}

	if(cname_flag==1)
	{
		cname=cJSON_PrintUnformatted(cname_array);
		if(cname!=NULL)
		{
			TLD_append(handle, (char *)"dns_cname", (void *)cname, TLD_TYPE_STRING);
			cJSON_free(cname);
			cname=NULL;
		}
	}

	cJSON_Delete(cname_array);
	cname_array=NULL;

	if(dns_info->rr_count>0)
	{
		cJSON * object=cJSON_CreateObject();
		get_rr_str2json(object, dns_info, &dns_sec);
		rr_buf=cJSON_PrintUnformatted(object);
		if(rr_buf!=NULL)
		{
			TLD_append(handle, (char *)"dns_rr", (void *)rr_buf, TLD_TYPE_STRING);
			cJSON_free(rr_buf);
			rr_buf=NULL;
		}
		cJSON_Delete(object);
		object=NULL;		
	}
	
	TLD_append(handle, (char *)"dns_sub", (void *)(long)dns_sec, TLD_TYPE_LONG);
	TLD_append(handle, (char *)"common_schema_type", (void *)"DNS", TLD_TYPE_STRING);

	log_msg.a_stream=a_stream;
	log_msg.result=result;
	log_msg.result_num=result_num;
	
	tsg_send_log(g_tsg_log_instance, handle, &log_msg, thread_seq);
	tsg_set_policy_flow(a_stream, result, a_stream->threadnum);
	return 0;
}

int fw_dns_select_monitor_result(struct streaminfo *a_stream, dns_info_t *dns_info, struct Maat_rule_t *result, int result_num, int thread_seq)
{
	for(int i=0; i<result_num; i++)
	{
		if(result[i].action!=TSG_ACTION_MONITOR)
		{
			continue;
		}
		
		tsg_notify_hited_monitor_result(a_stream, &(result[i]), 1, thread_seq);
		fw_dns_send_log(a_stream, dns_info, &(result[i]), 1, thread_seq);
	}

	return 0;
}

extern "C" char FW_DNS_PLUG_ENTRY(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	int ret=0,hit_num=0;
	scan_status_t mid=NULL;
	int category_id_num=0;
	char state=PROT_STATE_GIVEME;
	unsigned int category_id[MAX_CATEGORY_ID_NUM]={0};
	struct Maat_rule_t result[MAX_RESULT_NUM], *p_result=NULL;
	dns_info_t *dns_info=(dns_info_t *)session_info->app_info;

	if(dns_info==NULL || a_stream==NULL)
	{
		return state;
	}
	
	if(strlen((char *)dns_info->query_question.qname)==0)
	{		
		MESA_handle_runtime_log(g_fw_dns_plug_info.logger, 
									RLOG_LV_DEBUG,
									"DNS_PLUG",
									"Qname is %s, addr: %s",
									(dns_info==NULL) ? "NULL" : ((strlen((char *)dns_info->query_question.qname)==0) ? "NULL" : (char *)dns_info->query_question.qname),
									PRINTADDR(a_stream, g_fw_dns_plug_info.level)
								);
		return state;
	}
	
	ret=tsg_scan_nesting_addr(g_tsg_maat_feather, a_stream, PROTO_DNS, &mid, result, MAX_RESULT_NUM-hit_num);
	if(ret>0)
	{
		MESA_handle_runtime_log(g_fw_dns_plug_info.logger, 
									RLOG_LV_DEBUG,
									"SCAN_NEST_ADDR",
									"Hit policy_id: %d service: %d action: %d domain: %s qtype: %d addr: %s",								
									result[hit_num].config_id,
									result[hit_num].service_id,
									result[hit_num].action,
									(char *)dns_info->query_question.qname,
									dns_info->query_question.qtype,
									PRINTADDR(a_stream, g_fw_dns_plug_info.level)
								);
		hit_num+=ret;
	}
	else
	{
		MESA_handle_runtime_log(g_fw_dns_plug_info.logger, 
									RLOG_LV_DEBUG,
									"SCAN_NEST_ADDR",
									"Scan domain: %s qtype: %d ret: %d addr: %s",
									(char *)dns_info->query_question.qname,
									dns_info->query_question.qtype,
									ret,
									PRINTADDR(a_stream, g_fw_dns_plug_info.level)
								);
								
	}

	ret=Maat_full_scan_string(g_tsg_maat_feather,
									g_fw_dns_plug_info.table_qname_id,
									CHARSET_UTF8,
									(char *)dns_info->query_question.qname,
									strlen((char *)dns_info->query_question.qname),
									result+hit_num, 
									NULL,
									MAX_RESULT_NUM-hit_num,
									&mid,
									thread_seq
								);

	if(ret>0)
	{
		MESA_handle_runtime_log(g_fw_dns_plug_info.logger, 
									RLOG_LV_DEBUG,
									"SCAN_DOMAIN",
									"Hit domain: %s qtype: %d policy_id: %d service: %d action: %d addr: %s",
									(char *)dns_info->query_question.qname,
									dns_info->query_question.qtype,
									result[hit_num].config_id,
									result[hit_num].service_id,
									result[hit_num].action,
									PRINTADDR(a_stream, g_fw_dns_plug_info.level)
								);
		hit_num+=ret;
	}
	else
	{
		MESA_handle_runtime_log(g_fw_dns_plug_info.logger, 
									RLOG_LV_DEBUG,
									"SCAN_DOMAIN",
									"Scan domain: %s qtype: %d ret: %d addr: %s",
									(char *)dns_info->query_question.qname,
									dns_info->query_question.qtype,
									ret,
									PRINTADDR(a_stream, g_fw_dns_plug_info.level)
								);
								
	}

	category_id_num=tsg_get_fqdn_category_id(g_tsg_maat_feather, (char *)dns_info->query_question.qname, category_id, MAX_CATEGORY_ID_NUM, g_fw_dns_plug_info.logger, thread_seq);
	tsg_set_fqdn_category_id(a_stream, category_id, category_id_num, thread_seq);
	hit_num+=tsg_scan_fqdn_category_id(g_tsg_maat_feather, a_stream, result+hit_num,MAX_RESULT_NUM-hit_num, &mid, g_fw_dns_plug_info.table_qname_id, category_id, category_id_num, thread_seq);
	if(hit_num>0)
	{
		p_result=tsg_policy_decision_criteria(result, hit_num);
		switch(p_result->action)
		{
			case	TSG_ACTION_BYPASS:
				fw_dns_send_log(a_stream, dns_info, p_result, 1, thread_seq);
				break;
			case	TSG_ACTION_DENY:
				ret=tsg_is_do_deny_action_by_enforce_direction(a_stream, p_result);
				if(ret==0)
				{
					fw_dns_select_monitor_result(a_stream, dns_info, result, hit_num, thread_seq);
					break;
				}
				
				state=tsg_deal_deny_action(a_stream, p_result, PROTO_DNS, ACTION_RETURN_TYPE_PROT, (const void *)dns_info);
				if(state!=PROT_STATE_GIVEME)
				{
					fw_dns_send_log(a_stream, dns_info, p_result, 1, thread_seq);
				}
				break;
			case	TSG_ACTION_MONITOR:
				tsg_notify_hited_monitor_result(a_stream, result, hit_num, thread_seq);
				fw_dns_send_log(a_stream, dns_info, result, hit_num, thread_seq);
				break;
			default:
				break;
		}
	}

	if(mid!=NULL)
	{
		Maat_clean_status(&mid);
		mid=NULL;
	}

	return state;
}

extern "C" int FW_DNS_PLUG_INIT(void)
{
	memset(&g_fw_dns_plug_info, 0, sizeof(g_fw_dns_plug_info));

	MESA_load_profile_int_def(g_fw_dns_conffile, "DNS_PLUG", "LOG_LEVEL", &g_fw_dns_plug_info.level, RLOG_LV_FATAL);
	MESA_load_profile_string_def(g_fw_dns_conffile, "DNS_PLUG", "LOG_PATH", g_fw_dns_plug_info.log_path, sizeof(g_fw_dns_plug_info.log_path), "tsglog/fw_dns_plug/fw_dns_plug");


	MESA_load_profile_string_def(g_fw_dns_conffile, "DNS_PLUG", "TABLE_QNAME", g_fw_dns_plug_info.table_qname, MAX_TABLE_NAME_LEN, "TSG_FIELD_DNS_QNAME");

	g_fw_dns_plug_info.logger=MESA_create_runtime_log_handle(g_fw_dns_plug_info.log_path, g_fw_dns_plug_info.level);
	if(g_fw_dns_plug_info.logger==NULL)
	{
		printf("MESA_create_runtime_log_handle failed, log_path: %s level: %d", (g_fw_dns_plug_info.log_path==NULL) ? NULL : g_fw_dns_plug_info.log_path, g_fw_dns_plug_info.level);
		return -1;
	}

	g_fw_dns_plug_info.table_qname_id=Maat_table_register(g_tsg_maat_feather, g_fw_dns_plug_info.table_qname);
	if(g_fw_dns_plug_info.table_qname_id<0)
	{
		MESA_handle_runtime_log(g_fw_dns_plug_info.logger, RLOG_LV_FATAL, "REGISTER_TABLE", "Maat_table_register failed, table_name: %s", g_fw_dns_plug_info.table_qname);
		return -1;
	}
	
	return 0;
}


extern "C" void FW_DNS_PLUG_DESTROY(void)
{
	return ;
}

