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
#include "spp_hellosnort.h"

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

static void HelloSnortInit(struct _SnortConfig *sc,u_char *);
static void ParseTemplateArgs(char *);
static void HelloSnortFunct(Packet *);
static void PreprocCleanExitFunction(int, void *);
static void PreprocRestartFunction(int, void *);

#ifdef SNORT_RELOAD
static void HelloSnortReloadFuction(struct _SnortConfig *, char *, void **);
#endif

void SetupHelloSnort()
{
    /* 
     * link the preprocessor keyword to the init function in 
     * the preproc list 
     */
	#ifndef SNORT_RELOAD
		RegisterPreprocessor("Hello_Snort", HelloSnortInit);
	#else
		RegisterPreprocessor("Hello_Snort", HelloSnortInit,HelloSnortReloadFuction,NULL, NULL, NULL);
	#endif
}

/*
 * Function: HelloSnortInit(u_char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
static void HelloSnortInit(struct _SnortConfig *sc,u_char *args)
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
    AddFuncToPreprocList(sc,HelloSnortFunct,0x01, PP_HELLO_SNORT, PROTO_BIT__PROFINET);
	printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^HelloSnortInit ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^is setup\n\n");
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

/*
 * Function: PreprocFunction(Packet *)
 *
 * Purpose: Perform the preprocessor's intended function.  This can be
 *          simple (statistics collection) or complex (IP defragmentation)
 *          as you like.  Try not to destroy the performance of the whole
 *          system by trying to do too much....
 *
 * Arguments: p => pointer to the current packet data struct 
 *
 * Returns: void function
 *
 */
static void HelloSnortFunct(Packet *p)
{

    /* your preproc function goes here.... */

    /* 
     * if you need to issue an alert from your preprocessor, check out 
     * event_wrapper.h, there are some useful helper functions there
     */
	printf("the HelloSnort`s Main function HelloSnortFunct is here\n");
	uint8_t data_status = p->data[44];
	printf("0x%x\n",data_status);
	int a[8],i;
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
	
	if (PacketDataStatus.Reserved_2 || PacketDataStatus.Reserved_1)
	{
		//Should be zero
		SnortEventqAdd(GENERATOR_SPP_BO, BO_CLIENT_TRAFFIC_DETECT, 1, 0, 0,BO_CLIENT_TRAFFIC_DETECT_STR, 0);
	}
	
	PacketInfoList *tmp = idx;
	if(tmp == NULL)
	{
		printf("Init\n");
		idx = (PacketInfoList *)calloc(1,sizeof(PacketInfoList));
		idx->next = NULL;
		strcpy(idx->ether_dst,p->eh->ether_dst);
		strcpy(idx->ether_src,p->eh->ether_src); 
		idx->count = 1;
		printf("%02X:%02X:%02X:%02X:%02X:%02X -> ", idx->ether_src[0],
            idx->ether_src[1], idx->ether_src[2], idx->ether_src[3],
            idx->ether_src[4], idx->ether_src[5]);
		printf("%02X:%02X:%02X:%02X:%02X:%02X \n", idx->ether_dst[0],
            idx->ether_dst[1], idx->ether_dst[2], idx->ether_dst[3],
            idx->ether_dst[4], idx->ether_dst[5]);
	}
	else 
	{
		int end = 1;
		do{
			if(!strcmp(tmp->ether_dst,p->eh->ether_dst) && !strcmp(tmp->ether_src,p->eh->ether_src))
			{
				printf("Equal\n");
				tmp->count++;
				end = 0;
				break;
			}
			tmp = tmp -> next;
		} while(tmp != NULL);
		if(end)
		{
			printf("Not Equal\n");
			PacketInfoList *node = (PacketInfoList *)calloc(1,sizeof(PacketInfoList));
			node->next = idx;
			strcpy(node->ether_dst,p->eh->ether_dst);
			strcpy(node->ether_src,p->eh->ether_src); 
			node->count = 1;
			idx = node;
		}
	}	
	PrintTotal();
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



static void HelloSnortReloadFuction(struct _SnortConfig *sc, char *args, void **new_config)
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
