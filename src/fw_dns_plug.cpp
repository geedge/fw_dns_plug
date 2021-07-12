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
#include "fw_dns_plug.h"
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

#ifndef	PRINTADDR
#define	PRINTADDR(a, b)	((b)<RLOG_LV_FATAL ? printaddr(&(a->addr), a->threadnum) : "")
#endif

char FW_DNS_PLUG_VERSION_20210607=0;
struct fw_dns_plug g_fw_dns_plug_info;
char *g_fw_dns_conffile=(char *)"tsgconf/main.conf";

static int get_answer_ttl(cJSON *object)
{
	int min=0;
	int max=0;
	cJSON *item=NULL;

	if(object==NULL)
	{
		return 0;
	}
	
	item=cJSON_GetObjectItem(object, "min");
	min=item->valueint;

	item=cJSON_GetObjectItem(object, "max");
	max=item->valueint;

	return (rand()%(max-min+1)+min);
}

static cJSON * get_answer_records(cJSON *object, int qtype)
{
	int i=0;
	cJSON *item=NULL;
	int resolution_size=0;
	int answer_type=DNS_TYPE_UNKNOWN;
	
	cJSON *resolution_array=cJSON_GetObjectItem(object, "resolution");
	resolution_size=cJSON_GetArraySize(resolution_array);
	for(i=0; i<resolution_size; i++)
	{
		item=cJSON_GetArrayItem(resolution_array, i);
		cJSON *tmp=cJSON_GetObjectItem(item, "qtype");
		
		answer_type=fw_dns_type2index(tmp->valuestring);
		if(answer_type==qtype)
		{
			return cJSON_GetObjectItem(item, "answer");
		}
	}

	return NULL;
}

static int build_answer_records(struct streaminfo *a_stream, dns_info_t *dns_info, cJSON *object, cheat_pkt_opt_t *cheat_opt, int cheat_opt_num)
{
	int ttl=0;
	int record_id=0;
	int i=0,used_num=0;
	int answer_size=0;	
	cJSON *one_record=NULL;
	cJSON *a_item=NULL;	
	cJSON *answer_array=NULL;
	int answer_type=DNS_TYPE_UNKNOWN;

	answer_array=get_answer_records(object, dns_info->query_question.qtype);
	if(answer_array!=NULL)
	{
		memset(cheat_opt, 0, sizeof(cheat_pkt_opt_t)*cheat_opt_num);
		answer_size=cJSON_GetArraySize(answer_array);
		for(i=0; i<answer_size; i++)
		{
			one_record=cJSON_GetArrayItem(answer_array, i);
			a_item=cJSON_GetObjectItem(one_record, "atype");
			if(a_item==NULL)
			{
				continue;
			}
			
			answer_type=fw_dns_type2index(a_item->valuestring);
			a_item=cJSON_GetObjectItem(one_record, "ttl");
			ttl=get_answer_ttl(a_item);
				
			a_item=cJSON_GetObjectItem(one_record, "value");
			if(a_item!=NULL)
			{
				cheat_opt[used_num].res_type=answer_type;
				cheat_opt[used_num].cfg_type=answer_type;
				cheat_opt[used_num].ttl=ttl;

				switch(answer_type)
				{
					case	DNS_TYPE_A:
						cheat_opt[used_num].res_len=sizeof(unsigned int);
						inet_pton(AF_INET, a_item->valuestring, (void *)cheat_opt[used_num].res_info);
						break;
					case	DNS_TYPE_AAAA:
						cheat_opt[used_num].res_len=IPV6_ADDR_LEN;
						inet_pton(AF_INET6, a_item->valuestring, (void *)cheat_opt[used_num].res_info);
						break;
				case	DNS_TYPE_NS:
				case	DNS_TYPE_TXT:
				case	DNS_TYPE_PTR:
					case	DNS_TYPE_CNAME:
						cheat_opt[used_num].res_len=(strlen(a_item->valuestring) > sizeof(cheat_opt[used_num].res_info)-1) ? sizeof(cheat_opt[used_num].res_info)-1 : strlen(a_item->valuestring);
						memcpy(cheat_opt[used_num].res_info, a_item->valuestring, cheat_opt[used_num].res_len);
						break;
					default:
						continue;
				}
				used_num++;
			}
			else
			{
				a_item=cJSON_GetObjectItem(one_record, "record_id");
				record_id=a_item->valueint;

				a_item=cJSON_GetObjectItem(one_record, "selected_num");
				used_num+=dns_get_cheat_opt(record_id, a_item->valueint, ttl, answer_type, cheat_opt+used_num, cheat_opt_num-used_num);
			}
		}
	}

	return used_num;
}

static char fw_dns_action(struct streaminfo *a_stream, dns_info_t *dns_info, Maat_rule_t *p_result, const void *a_packet)
{
	int ret=0;
	int payload_len=0;
	int answer_records_num=0;
	dns_hdr_t *dns_hdr = NULL;
	cJSON *item=NULL;
	cJSON *object=NULL;
	char *tmp_buff=NULL;
	unsigned char senddir=0;
	char state=PROT_STATE_GIVEME;
	int method_type=TSG_METHOD_TYPE_UNKNOWN;
	cheat_pkt_opt_t cheat_opt[MAX_ANSWER_RECORDS_NUM];
	unsigned char cheat_pkt_payload[MAX_CHEAT_PKT_PAYLOAD_LEN];
	
	tmp_buff=(char *)calloc(1, p_result->serv_def_len+1);
	Maat_read_rule(g_tsg_maat_feather, p_result, MAAT_RULE_SERV_DEFINE, tmp_buff, p_result->serv_def_len);
	
	object=cJSON_Parse(tmp_buff);
	if(object==NULL)
	{
		MESA_handle_runtime_log(g_fw_dns_plug_info.logger, 
								RLOG_LV_FATAL,
								"DO_ACTION",
								"Hit policy_id: %d service: %d action: %d user_reagion: %s domain: %s qtype: %d addr: %s",
								p_result->config_id,
								p_result->service_id,
								p_result->action,
								(tmp_buff==NULL) ? p_result->service_defined : tmp_buff,
								(char *)dns_info->query_question.qname,
								dns_info->query_question.qtype,
								PRINTADDR(a_stream, g_fw_dns_plug_info.level)
								);
		method_type=TSG_METHOD_TYPE_DROP;
	}
	else
	{
		item=cJSON_GetObjectItem(object, "method");
		if(item!=NULL)
		{
			method_type=tsg_get_method_id(item->valuestring);
		}
	}
	
	switch(method_type)
	{
		case	TSG_METHOD_TYPE_DROP:
			state=PROT_STATE_GIVEME|PROT_STATE_DROPPKT;
			break;
		case	TSG_METHOD_TYPE_REDIRECTION:
			if(g_fw_dns_plug_info.mode==0 && dns_info->hdr_info.qr==1) //mirror
			{
				break;
			}

			if(g_fw_dns_plug_info.mode==1 && dns_info->hdr_info.qr==0) //inline or transparent
			{
				break;
			}
			
			answer_records_num=build_answer_records(a_stream, dns_info, object, cheat_opt, MAX_ANSWER_RECORDS_NUM);
			if(answer_records_num<=0)
			{
				MESA_handle_runtime_log(g_fw_dns_plug_info.logger, 
										RLOG_LV_FATAL,
										"DO_ACTION",
										"Hit policy_id: %d service: %d action: %d user_region: %s domain: %s qtype: %d addr: %s",
										p_result->config_id,
										p_result->service_id,
										p_result->action,
										(tmp_buff==NULL) ? p_result->service_defined : tmp_buff,
										(char *)dns_info->query_question.qname,
										dns_info->query_question.qtype,
										PRINTADDR(a_stream, g_fw_dns_plug_info.level)
									);
				state=PROT_STATE_GIVEME|PROT_STATE_DROPPKT;
				break;
			}
			
			memset(cheat_pkt_payload, 0, MAX_CHEAT_PKT_PAYLOAD_LEN);
			dns_hdr = (dns_hdr_t *)cheat_pkt_payload;
			dns_hdr->id = dns_info->hdr_info.id;
			dns_hdr->qdcount = 1;
			dns_hdr->ancount = answer_records_num;
			
			payload_len=build_cheat_pkt(cheat_pkt_payload, MAX_CHEAT_PKT_PAYLOAD_LEN, &dns_info->query_question, cheat_opt, answer_records_num);
			if(payload_len==-1)
			{
				MESA_handle_runtime_log(g_fw_dns_plug_info.logger, 
							RLOG_LV_FATAL,
							"DO_ACTION",
							"Hit policy_id: %d service: %d action: %d build_cheat_pkt ret: %d addr: %s",
							p_result->config_id,
							p_result->service_id,
							p_result->action,
							payload_len,
							PRINTADDR(a_stream, g_fw_dns_plug_info.level)
							);
				break;
			}

            if(dns_info->hdr_info.qr==0)
            {
			    senddir = MESA_dir_reverse(a_stream->routedir);
            }
            else
            {
                senddir = a_stream->routedir;
            }
			ret=MESA_inject_pkt(a_stream, (const char *)cheat_pkt_payload, payload_len, (const char *)a_packet, senddir);
			if(ret<0)
			{
				MESA_handle_runtime_log(g_fw_dns_plug_info.logger,
											RLOG_LV_FATAL,
											"SEND_CHEAT_PKT",
											"Return of MESA_inject_pkt_feedback function is %d, qname: %s qtype: %d cfg_id: %d service: %d addr: %s",
											ret,
											dns_info->query_question.qname,
											dns_info->query_question.qtype,
											p_result->config_id,
											p_result->service_id,
											PRINTADDR(a_stream, g_fw_dns_plug_info.level)
											);
			}
			state=PROT_STATE_GIVEME|PROT_STATE_DROPPKT;
			break;
		default:
			break;
	}

	if(object!=NULL)
	{
		cJSON_Delete(object);
		object=NULL;
	}
	
	if(tmp_buff!=NULL)
	{
		free(tmp_buff);
		tmp_buff=NULL;
	}
	
	return state;
}

static int fw_dns_send_log(struct streaminfo *a_stream, dns_info_t *dns_info, struct Maat_rule_t *result, int result_num, int thread_seq)
{
	int i=0;
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
			}
		}
	}

	cname=cJSON_PrintUnformatted(cname_array);
	if(cname!=NULL && strlen(cname)>0)
	{
		TLD_append(handle, (char *)"dns_cname", (void *)cname, TLD_TYPE_STRING);
		cJSON_free(cname);
		cname=NULL;
	}
	cJSON_Delete(cname_array);
	cname_array=NULL;
	
	cJSON * object=cJSON_CreateObject();
	get_rr_str2json(object, dns_info, &dns_sec);
	rr_buf=cJSON_PrintUnformatted(object);
	TLD_append(handle, (char *)"dns_rr", (void *)rr_buf, TLD_TYPE_STRING);
	
	cJSON_Delete(object);
	object=NULL;

	cJSON_free(rr_buf);
	rr_buf=NULL;
	
	TLD_append(handle, (char *)"dns_sub", (void *)(long)dns_sec, TLD_TYPE_LONG);

	TLD_append(handle, (char *)"common_schema_type", (void *)"DNS", TLD_TYPE_STRING);

	log_msg.a_stream=a_stream;
	log_msg.result=result;
	log_msg.result_num=result_num;
	
	tsg_send_log(g_tsg_log_instance, handle, &log_msg, thread_seq);
	tsg_set_policy_flow(a_stream, result, a_stream->threadnum);
	return 0;
}

extern "C" char FW_DNS_PLUG_ENTRY(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	int i=0,ret=0,hit_num=0;
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
	for(i=0; i< category_id_num; i++)
	{
		ret=Maat_scan_intval(g_tsg_maat_feather, g_fw_dns_plug_info.table_qname_id, (unsigned int)category_id[i], result+hit_num,MAX_RESULT_NUM-hit_num, &mid, thread_seq);
		if(ret>0)
		{
			MESA_handle_runtime_log(g_fw_dns_plug_info.logger, 
										RLOG_LV_DEBUG,
										"SCAN_FQDN_CAT_ID",
										"Hit qname: %s category id: %d policy_id: %d service: %d action: %d addr: %s",
										(char *)dns_info->query_question.qname,
										category_id[i],
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
										"Scan domain: %s category id: %d ret: %d addr: %s",
										(char *)dns_info->query_question.qname,
										category_id[i],
										ret,
										PRINTADDR(a_stream, g_fw_dns_plug_info.level)
									);
									
		}
	}
	
	if(hit_num>0)
	{
		p_result=tsg_fetch_deny_rule(result, hit_num);
		
		if(p_result!=NULL)
		{
			state=fw_dns_action(a_stream, dns_info, p_result, a_packet);
			if(state!=PROT_STATE_GIVEME)
			{
				fw_dns_send_log(a_stream, dns_info, p_result, 1, thread_seq);
			}
		}
		else
		{
			fw_dns_send_log(a_stream, dns_info, result, hit_num, thread_seq);
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
	int ret=0,len=0;
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

	ret=fw_dns_rule_init(g_fw_dns_conffile, g_fw_dns_plug_info.logger);
	if(ret<0)
	{
		return -1;
	}

	len=sizeof(g_fw_dns_plug_info.s_mode);
	ret=sapp_get_platform_opt(SPO_DEPLOYMENT_MODE_STR, g_fw_dns_plug_info.s_mode, &len);
	if(ret>=0)
	{
		if((memcmp(g_fw_dns_plug_info.s_mode, "mirror", strlen(g_fw_dns_plug_info.s_mode)))==0 || (memcmp(g_fw_dns_plug_info.s_mode, "dumpfile", strlen(g_fw_dns_plug_info.s_mode)))==0)
		{
			g_fw_dns_plug_info.mode=0;
		}
		else
		{
			g_fw_dns_plug_info.mode=1;
		}
	}
	
	return 0;
}


extern "C" void FW_DNS_PLUG_DESTROY(void)
{
	return ;
}

