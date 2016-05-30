/* $Id$ */
/* Snort Preprocessor Plugin Source File Template */

/* spp_template 
 * 
 * Arguments:
 *   
 * This is the list of arguements that the plugin can take at the 
 * "preprocessor" line in the rules file
 *
 * Effect:
 *
 * What the preprocessor does.  Check out some of the default ones 
 * (e.g. spp_frag2) for a good example of this description.
 *
 */

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <rpc/types.h>

/*
 * If you're going to issue any alerts from this preproc you 
 * should include generators.h and event_wrapper.h
 */
#include "generators.h"
#include "event_wrapper.h"

#include "util.h"
#include "plugbase.h"
#include "parser.h"

/*
 * put in other inculdes as necessary
 */

/* 
 * your preprocessor header file goes here if necessary, don't forget
 * to include the header file in plugbase.h too!
 */
#include "spp_profinet.h"

/*
 * define any needed data structs for things like configuration
 */
typedef struct _TemplateData
{
	uint64_t count;
    /* Your struct members here */
} TemplateData;

typedef struct _DataStatus
{
	uint8_t Ignore;
	uint8_t Reserved_2;
	uint8_t StationProblemIndicator;
	uint8_t ProviderState;
	uint8_t Reserved_1;
	uint8_t DataValid;
	uint8_t Redundancy;
	uint8_t State;
    char    *pszProtAddInfo;
    char    *pszProtShort;
    char    *pszProtSummary;
    char    *pszProtComment;
    char    szFieldSummary[100];
    int     bCyclic;
} DataStatus;

typedef struct _PacketInfoList
{
	uint8_t ether_dst[6];
	uint8_t ether_src[6];
    uint64_t count;
	struct _PacketInfoList *next;
} PacketInfoList;


/* 
 * If you need to instantiate the preprocessor's 
 * data structure, do it here 
 */
TemplateData SomeData;
DataStatus PacketDataStatus;
PacketInfoList *idx;
/* 
 * function prototypes go here
 */

static void ProfinetRTInit(struct _SnortConfig *sc,u_char *);
static void SetPactekStatus(Packet *);
static void ParseTemplateArgs(char *);
static void ProfinetRTFunct(Packet *);
static void PreprocCleanExitFunction(int, void *);
static void PreprocRestartFunction(int, void *);
static void ProfinetPrintStats(int);

#ifdef SNORT_RELOAD
static void ProfinetRTReloadFuction(struct _SnortConfig *, char *, void **);
#endif

void SetupProfinet()
{
	#ifndef SNORT_RELOAD
		RegisterPreprocessor("Profinet_RT", ProfinetRTInit);
	#else
		RegisterPreprocessor("Profinet_RT", ProfinetRTInit, ProfinetRTReloadFuction,NULL, NULL, NULL);
	#endif
}

static void SetPactekStatus(Packet *p)
{
	int a[8],i;
	uint8_t data_status = p->data[p->dsize - 2];
	for (i = 0; i != 8; ++i)
	{
		a[8 - 1 - i] = data_status % 2;
		data_status /= 2;
	}
	PacketDataStatus.Ignore = a[0];
	PacketDataStatus.Reserved_2 = a[1];
	PacketDataStatus.StationProblemIndicator = a[2];
	PacketDataStatus.ProviderState = a[3];
	PacketDataStatus.Reserved_1 = a[4];
	PacketDataStatus.DataValid = a[5];
	PacketDataStatus.Redundancy = a[6];
	PacketDataStatus.State = a[7];	
	
	uint16_t frame_id;
	frame_id = ntohs(p->proh->frame_id);
	if (frame_id <= 0x001F) {
        PacketDataStatus.pszProtShort    = "PN-RT";
        PacketDataStatus.pszProtAddInfo  = "Reserved, ";
        PacketDataStatus.pszProtSummary  = "Real-Time";
        PacketDataStatus.pszProtComment  = "0x0000-0x001F: Reserved ID";
        PacketDataStatus.bCyclic         = 0;
    } else if (frame_id <= 0x0021) {
        PacketDataStatus.pszProtShort    = "PN-PTCP";
        PacketDataStatus.pszProtAddInfo  = "Synchronization, ";
        PacketDataStatus.pszProtSummary  = "Real-Time";
        PacketDataStatus.pszProtComment  = "0x0020-0x0021: Real-Time: Sync (with follow up)";
        PacketDataStatus.bCyclic         = 0;
    } else if (frame_id <= 0x007F) {
        PacketDataStatus.pszProtShort    = "PN-RT";
        PacketDataStatus.pszProtAddInfo  = "Reserved, ";
        PacketDataStatus.pszProtSummary  = "Real-Time";
        PacketDataStatus.pszProtComment  = "0x0022-0x007F: Reserved ID";
        PacketDataStatus.bCyclic         = 0;
    } else if (frame_id <= 0x0081) {
        PacketDataStatus.pszProtShort    = "PN-PTCP";
        PacketDataStatus.pszProtAddInfo  = "Synchronization, ";
        PacketDataStatus.pszProtSummary  = "Isochronous-Real-Time";
        PacketDataStatus.pszProtComment  = "0x0080-0x0081: Real-Time: Sync (without follow up)";
        PacketDataStatus.bCyclic         = 0;
    } else if (frame_id <= 0x00FF) {
        PacketDataStatus.pszProtShort    = "PN-RT";
        PacketDataStatus.pszProtAddInfo  = "Reserved, ";
        PacketDataStatus.pszProtSummary  = "Real-Time";
        PacketDataStatus.pszProtComment  = "0x0082-0x00FF: Reserved ID";
        PacketDataStatus.bCyclic         = 0;
    } else if (frame_id <= 0x6FF) {
        PacketDataStatus.pszProtShort    = "PN-RTC3";
        PacketDataStatus.pszProtAddInfo  = "RTC3, ";
        PacketDataStatus.pszProtSummary  = "Isochronous-Real-Time";
        PacketDataStatus.pszProtComment  = "0x0100-0x06FF: RED: Real-Time(class=3): non redundant, normal or DFP";
        PacketDataStatus.bCyclic         = 1;
    } else if (frame_id <= 0x0FFF) {
        PacketDataStatus.pszProtShort    = "PN-RTC3";
        PacketDataStatus.pszProtAddInfo  = "RTC3, ";
        PacketDataStatus.pszProtSummary  = "Isochronous-Real-Time";
        PacketDataStatus.pszProtComment  = "0x0700-0x0FFF: RED: Real-Time(class=3): redundant, normal or DFP";
        PacketDataStatus.bCyclic         = 1;
    } else if (frame_id <= 0x7FFF) {
        PacketDataStatus.pszProtShort    = "PN-RT";
        PacketDataStatus.pszProtAddInfo  = "Reserved, ";
        PacketDataStatus.pszProtSummary  = "Real-Time";
        PacketDataStatus.pszProtComment  = "0x1000-0x7FFF: Reserved ID";
        PacketDataStatus.bCyclic         = 0;
    } else if (frame_id <= 0xBBFF) {
        PacketDataStatus.pszProtShort    = "PN-RTC1";
        PacketDataStatus.pszProtAddInfo  = "RTC1, ";
        PacketDataStatus.pszProtSummary  = "cyclic Real-Time";
        PacketDataStatus.pszProtComment  = "0x8000-0xBBFF: Real-Time(class=1 unicast): non redundant, normal";
        PacketDataStatus.bCyclic         = 1;
    } else if (frame_id <= 0xBFFF) {
        PacketDataStatus.pszProtShort    = "PN-RTC1";
        PacketDataStatus.pszProtAddInfo  = "RTC1, ";
        PacketDataStatus.pszProtSummary  = "cyclic Real-Time";
        PacketDataStatus.pszProtComment  = "0xBC00-0xBFFF: Real-Time(class=1 multicast): non redundant, normal";
        PacketDataStatus.bCyclic         = 1;
    } else if (frame_id <= 0xF7FF) {
        /* check if udp frame on PNIO port */
		/*
        if (pinfo->destport == 0x8892)
        { 	//UDP frame
            PacketDataStatus.pszProtShort = "PN-RTCUDP,";
            PacketDataStatus.pszProtAddInfo = "RT_CLASS_UDP, ";
            PacketDataStatus.pszProtComment = "0xC000-0xF7FF: Real-Time(UDP unicast): Cyclic";
        }
        else
        { 	//layer 2 frame
            PacketDataStatus.pszProtShort = "PN-RT";
            PacketDataStatus.pszProtAddInfo = "RTC1(legacy), ";
            PacketDataStatus.pszProtComment = "0xC000-0xF7FF: Real-Time(class=1 unicast): Cyclic";
        } */
		PacketDataStatus.pszProtShort = "PN-RT";
        PacketDataStatus.pszProtAddInfo = "RTC1(legacy), ";
        PacketDataStatus.pszProtComment = "0xC000-0xF7FF: Real-Time(class=1 unicast): Cyclic";
        PacketDataStatus.pszProtSummary  = "cyclic Real-Time";
        PacketDataStatus.bCyclic         = 1;
    } else if (frame_id <= 0xFBFF) {
		/*
        if (pinfo->destport == 0x8892)
        {   //UDP frame
            PacketDataStatus.pszProtShort = "PN-RTCUDP,";
            PacketDataStatus.pszProtAddInfo = "RT_CLASS_UDP, ";
            PacketDataStatus.pszProtComment = "0xF800-0xFBFF:: Real-Time(UDP multicast): Cyclic";
        }
        else
        {   //layer 2 frame
            PacketDataStatus.pszProtShort = "PN-RT";
            PacketDataStatus.pszProtAddInfo = "RTC1(legacy), ";
            PacketDataStatus.pszProtComment = "0xF800-0xFBFF: Real-Time(class=1 multicast): Cyclic";
         }*/
		PacketDataStatus.pszProtShort = "PN-RT";
        PacketDataStatus.pszProtAddInfo = "RTC1(legacy), ";
        PacketDataStatus.pszProtComment = "0xF800-0xFBFF: Real-Time(class=1 multicast): Cyclic";
        PacketDataStatus.pszProtSummary  = "cyclic Real-Time";
        PacketDataStatus.bCyclic         = 1;
    } else if (frame_id <= 0xFDFF) {
        PacketDataStatus.pszProtShort    = "PN-RTA";
        PacketDataStatus.pszProtAddInfo  = "Reserved, ";
        PacketDataStatus.pszProtSummary  = "acyclic Real-Time";
        PacketDataStatus.pszProtComment  = "0xFC00-0xFDFF: Reserved";
        PacketDataStatus.bCyclic         = 0;
        if (frame_id == 0xfc01) {
            PacketDataStatus.pszProtShort    = "PN-RTA";
            PacketDataStatus.pszProtAddInfo  = "Alarm High, ";
            PacketDataStatus.pszProtSummary  = "acyclic Real-Time";
            PacketDataStatus.pszProtComment  = "Real-Time: Acyclic PN-IO Alarm high priority";
        }

    } else if (frame_id <= 0xFEFF) {
        PacketDataStatus.pszProtShort    = "PN-RTA";
        PacketDataStatus.pszProtAddInfo  = "Reserved, ";
        PacketDataStatus.pszProtSummary  = "acyclic Real-Time";
        PacketDataStatus.pszProtComment  = "0xFE00-0xFEFF: Real-Time: Reserved";
        PacketDataStatus.bCyclic         = 0;
        if (frame_id == 0xFE01) {
            PacketDataStatus.pszProtShort    = "PN-RTA";
            PacketDataStatus.pszProtAddInfo  = "Alarm Low, ";
            PacketDataStatus.pszProtSummary  = "acyclic Real-Time";
            PacketDataStatus.pszProtComment  = "Real-Time: Acyclic PN-IO Alarm low priority";
        }
        if (frame_id == 0xfefc) {
            PacketDataStatus.pszProtShort    = "PN-RTA";
            PacketDataStatus.pszProtAddInfo  = "";
            PacketDataStatus.pszProtSummary  = "acyclic Real-Time";
            PacketDataStatus.pszProtComment  = "Real-Time: DCP (Dynamic Configuration Protocol) hello";
        }
        if (frame_id == 0xfefd) {
            PacketDataStatus.pszProtShort    = "PN-RTA";
            PacketDataStatus.pszProtAddInfo  = "";
            PacketDataStatus.pszProtSummary  = "acyclic Real-Time";
            PacketDataStatus.pszProtComment  = "Real-Time: DCP (Dynamic Configuration Protocol) get/set";
        }
        if (frame_id == 0xfefe) {
            PacketDataStatus.pszProtShort    = "PN-RTA";
            PacketDataStatus.pszProtAddInfo  = "";
            PacketDataStatus.pszProtSummary  = "acyclic Real-Time";
            PacketDataStatus.pszProtComment  = "Real-Time: DCP (Dynamic Configuration Protocol) identify multicast request";
        }
        if (frame_id == 0xfeff) {
            PacketDataStatus.pszProtShort    = "PN-RTA";
            PacketDataStatus.pszProtAddInfo  = "";
            PacketDataStatus.pszProtSummary  = "acyclic Real-Time";
            PacketDataStatus.pszProtComment  = "Real-Time: DCP (Dynamic Configuration Protocol) identify response";
        }
    } else if (frame_id <= 0xFF01) {
        PacketDataStatus.pszProtShort    = "PN-PTCP";
        PacketDataStatus.pszProtAddInfo  = "RTA Sync, ";
        PacketDataStatus.pszProtSummary  = "acyclic Real-Time";
        PacketDataStatus.pszProtComment  = "0xFF00-0xFF01: PTCP Announce";
        PacketDataStatus.bCyclic         = 0;
    } else if (frame_id <= 0xFF1F) {
        PacketDataStatus.pszProtShort    = "PN-PTCP";
        PacketDataStatus.pszProtAddInfo  = "RTA Sync, ";
        PacketDataStatus.pszProtSummary  = "acyclic Real-Time";
        PacketDataStatus.pszProtComment  = "0xFF02-0xFF1F: Reserved";
        PacketDataStatus.bCyclic         = 0;
    } else if (frame_id <= 0xFF21) {
        PacketDataStatus.pszProtShort    = "PN-PTCP";
        PacketDataStatus.pszProtAddInfo  = "Follow Up, ";
        PacketDataStatus.pszProtSummary  = "acyclic Real-Time";
        PacketDataStatus.pszProtComment  = "0xFF20-0xFF21: PTCP Follow Up";
        PacketDataStatus.bCyclic         = 0;
    } else if (frame_id <= 0xFF22) {
        PacketDataStatus.pszProtShort    = "PN-PTCP";
        PacketDataStatus.pszProtAddInfo  = "Follow Up, ";
        PacketDataStatus.pszProtSummary  = "acyclic Real-Time";
        PacketDataStatus.pszProtComment  = "0xFF22-0xFF3F: Reserved";
        PacketDataStatus.bCyclic         = 0;
    } else if (frame_id <= 0xFF43) {
        PacketDataStatus.pszProtShort    = "PN-PTCP";
        PacketDataStatus.pszProtAddInfo  = "Delay, ";
        PacketDataStatus.pszProtSummary  = "acyclic Real-Time";
        PacketDataStatus.pszProtComment  = "0xFF40-0xFF43: Acyclic Real-Time: Delay";
        PacketDataStatus.bCyclic         = 0;
    } else if (frame_id <= 0xFF7F) {
        PacketDataStatus.pszProtShort    = "PN-RT";
        PacketDataStatus.pszProtAddInfo  = "Reserved, ";
        PacketDataStatus.pszProtSummary  = "Real-Time";
        PacketDataStatus.pszProtComment  = "0xFF44-0xFF7F: reserved ID";
        PacketDataStatus.bCyclic         = 0;
    } else if (frame_id <= 0xFF8F) {
        PacketDataStatus.pszProtShort    = "PN-RT";
        PacketDataStatus.pszProtAddInfo  = "";
        PacketDataStatus.pszProtSummary  = "Fragmentation";
        PacketDataStatus.pszProtComment  = "0xFF80-0xFF8F: Fragmentation";
        PacketDataStatus.bCyclic         = 0;
    } else {
        PacketDataStatus.pszProtShort    = "PN-RT";
        PacketDataStatus.pszProtAddInfo  = "Reserved, ";
        PacketDataStatus.pszProtSummary  = "Real-Time";
        PacketDataStatus.pszProtComment  = "0xFF90-0xFFFF: reserved ID";
        PacketDataStatus.bCyclic         = 0;
    }

}

static void ProfinetRTInit(struct _SnortConfig *sc,u_char *args)
{
    /* 
     * parse the argument list from the rules file 
     */
    //ParseTemplateArgs(args);

    /* 
     * perform any other initialization functions that are required here
     */

    /* 
     * Set the preprocessor function into the function list 
     */
    AddFuncToPreprocList(sc,ProfinetRTFunct,0x01, PP_Profinet_RT, PROTO_BIT__PROFINET);
	printf("ProfinetRTInit is setup\n\n");
	RegisterPreprocStats("Profinet_RT", ProfinetPrintStats);
    //AddFuncToCleanExitList(PreprocCleanExitFunction, NULL);
    //AddFuncToRestartList(PreprocRestartFunction, NULL);
}



/*
 * Function: ParseTemplateArgs(char *)
 *
 * Purpose: Process the preprocessor arguements from the rules file and 
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init 
 *          function.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 *
 */
static void ParseTemplateArgs(char *args)
{
    /* your parsing function goes here, check out the other spp files
       for examples */
}
static void PrintTotal()
{
	PacketInfoList *tmp = idx;
	if(tmp != NULL)
	{
		do
		{
		    printf("%02X:%02X:%02X:%02X:%02X:%02X -> ", tmp->ether_src[0],
				tmp->ether_src[1], tmp->ether_src[2], tmp->ether_src[3],
				tmp->ether_src[4], tmp->ether_src[5]);
			printf("%02X:%02X:%02X:%02X:%02X:%02X ", tmp->ether_dst[0],
				tmp->ether_dst[1], tmp->ether_dst[2], tmp->ether_dst[3],
				tmp->ether_dst[4], tmp->ether_dst[5]);
			printf(" Count: %d\n",tmp->count);
			tmp = tmp->next;
		}
		while(tmp != NULL);
	}
	
}


static void ProfinetRTFunct(Packet *p)
{

    /* 
     * if you need to issue an alert from your preprocessor, check out 
     * event_wrapper.h, there are some useful helper functions there
     */
	printf("the HelloSnort`s Main function ProfinetRTFunct is here\n");
	SetPactekStatus(p);
	SnortEventqAdd(146, 1, 1, 0, 0,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0);
	if (PacketDataStatus.Reserved_2 || PacketDataStatus.Reserved_1)
	{
		//Should be zero
		SnortEventqAdd(146, 1, 1, 0, 0,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0);
	}	
	if (!strcmp(PacketDataStatus.pszProtAddInfo,"Reserved, "))
	{
		//Reserved FrameID
		SnortEventqAdd(GENERATOR_SPP_BO, BO_CLIENT_TRAFFIC_DETECT, 1, 0, 0,BO_CLIENT_TRAFFIC_DETECT_STR, 0);
	}
	
	PacketInfoList *tmp = idx;
	int i;
	if(tmp == NULL)
	{
		printf("Init\n");
		idx = (PacketInfoList *)calloc(1,sizeof(PacketInfoList));
		idx->next = NULL;
		for(i=0;i<6;i++)
		{
			idx->ether_src[i] = p->eh->ether_src[i];
			idx->ether_dst[i] = p->eh->ether_dst[i];
		}
		idx->count = 1;
	}
	else 
	{
		int end = 1;
		do{
			if(!memcmp(tmp->ether_dst,p->eh->ether_dst,6) && !memcmp(tmp->ether_src,p->eh->ether_src,6))
			{
				tmp->count++;
				end = 0;
				break;
			}
			tmp = tmp -> next;
		} while(tmp != NULL);
		if(end)
		{
			PacketInfoList *node = (PacketInfoList *)calloc(1,sizeof(PacketInfoList));
			node->next = idx;
			for(i=0;i<6;i++)
			{
				node->ether_src[i] = p->eh->ether_src[i];
				node->ether_dst[i] = p->eh->ether_dst[i];
			}
			node->count = 1;
			idx = node;
		}
	}	
	//PrintTotal();
}


/* 
 * Function: PreprocCleanExitFunction(int, void *)
 *
 * Purpose: This function gets called when Snort is exiting, if there's
 *          any cleanup that needs to be performed (e.g. closing files)
 *          it should be done here.
 *
 * Arguments: signal => the code of the signal that was issued to Snort
 *            data => any arguments or data structs linked to this 
 *                    functioin when it was registered, may be
 *                    needed to properly exit
 *       
 * Returns: void function
 */                   
static void PreprocCleanExitFunction(int signal, void *data)
{
       /* clean exit code goes here */
}



static void ProfinetRTReloadFuction(struct _SnortConfig *sc, char *args, void **new_config)
{
	printf("Call the reload  hellosnort\n\n\n");
} 

/* 
 * Function: PreprocRestartFunction(int, void *)
 *
 * Purpose: This function gets called when Snort is restarting on a SIGHUP,
 *          if there's any initialization or cleanup that needs to happen
 *          it should be done here.
 *
 * Arguments: signal => the code of the signal that was issued to Snort
 *            data => any arguments or data structs linked to this 
 *                    functioin when it was registered, may be
 *                    needed to properly exit
 *       
 * Returns: void function
 */                   
static void PreprocRestartFunction(int signal, void *foo)
{
       /* restart code goes here */
}



//RegisterPreprocStats 用来Snort最后退出的时候输出最后结果
static void ProfinetPrintStats(int exiting)
{
	PacketInfoList *tmp = idx;
	if(tmp != NULL)
	{
		do
		{
		    printf("%02X:%02X:%02X:%02X:%02X:%02X -> ", tmp->ether_src[0],
				tmp->ether_src[1], tmp->ether_src[2], tmp->ether_src[3],
				tmp->ether_src[4], tmp->ether_src[5]);
			printf("%02X:%02X:%02X:%02X:%02X:%02X ", tmp->ether_dst[0],
				tmp->ether_dst[1], tmp->ether_dst[2], tmp->ether_dst[3],
				tmp->ether_dst[4], tmp->ether_dst[5]);
			printf(" Count: %d\n",tmp->count);
			tmp = tmp->next;
		}
		while(tmp != NULL);
	}
	/*
	LogMessage("Profinet statistics:\n");
    LogMessage("        Total Fragments: %u\n", f3stats.total);
    LogMessage("      Frags Reassembled: %u\n", f3stats.reassembles);
    LogMessage("               Discards: %u\n", f3stats.discards);
    LogMessage("          Memory Faults: %u\n", f3stats.prunes);
    LogMessage("               Timeouts: %u\n", f3stats.timeouts);
    LogMessage("               Overlaps: %u\n", f3stats.overlaps);
    LogMessage("              Anomalies: %u\n", f3stats.anomalies);
    LogMessage("                 Alerts: %u\n", f3stats.alerts);
    LogMessage("                  Drops: %u\n", f3stats.drops);
    LogMessage("     FragTrackers Added: %u\n", f3stats.fragtrackers_created);
    LogMessage("    FragTrackers Dumped: %u\n", f3stats.fragtrackers_released);
    LogMessage("FragTrackers Auto Freed: %u\n", f3stats.fragtrackers_autoreleased);
    LogMessage("    Frag Nodes Inserted: %u\n", f3stats.fragnodes_created);
    LogMessage("     Frag Nodes Deleted: %u\n", f3stats.fragnodes_released);
	*/
}