/** @file

  geoip_db: A plugin to interface with the MaxMind, Inc. GeoIP library.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include <stdio.h>
#include <ts/ts.h>
#include <ts/remap.h>
#include <sys/types.h>
#include <string.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <ts/ink_defs.h>
#include <ts/ink_atomic.h>

#if HAVE_GEOIP_H
#include <GeoIP.h>
#endif

// ----------------------------------------------------------------------
// GeoIP DB Definitions
// ----------------------------------------------------------------------

#define MAX_GEOIP_DB 255    // maximum number of DBs
#define MAX_GEOIP_DB_TAG 8  // maximum tag length (will error)

typedef const char *(*GeoIP_DB_func_t)(const char *, const char *);
const char *GeoIP_DB_Lookup(const char *tag, const char *ipaddr);
GeoIP_DB_func_t GeoIP_DB_Lookup_handle = &GeoIP_DB_Lookup;

struct GeoIP_DB {
  char *tag;
  char *filename;
  GeoIP *object;
};

GeoIP_DB *GeoIP_DBs[MAX_GEOIP_DB];
GeoIP *GeoIP_DB_Default = NULL;
int GeoIP_DB_Total = 0;

// ----------------------------------------------------------------------
// Perform IPv4 "a.b.c.d" -to- Country-Code Look Up
// ----------------------------------------------------------------------

const char *GeoIP_DB_Lookup(const char *tag, const char *ipaddr) {
  int country_id = 0;
  const char *country_code;
  const char *country_name;
  unsigned long ipnum;

  TSDebug("geoip_db","GeoIP_DB_Lookup():");
  TSDebug("geoip_db","  tag    = '%s'", tag);
  TSDebug("geoip_db","  ipaddr = '%s'", ipaddr);

  ipnum = GeoIP_addr_to_num(ipaddr);
  if (strcmp(tag,"")==0) {
    country_id = GeoIP_id_by_ipnum(GeoIP_DB_Default, ipnum);
  }
  else {
    for (int x = 0; x < GeoIP_DB_Total; x++) {
      if (strcmp(tag,GeoIP_DBs[x]->tag) == 0) {
	country_id = GeoIP_id_by_ipnum(GeoIP_DBs[x]->object, ipnum);
	TSDebug("geoip_db","  Lookup using DB Tag '%s'", GeoIP_DBs[x]->tag);
      }
    }
  }
  country_code = GeoIP_country_code[country_id];
  country_name = GeoIP_country_name[country_id];
  TSDebug("geoip_db","  RESULT = '%s' -- '%s'", country_code, country_name);
  return country_code;
}

// ----------------------------------------------------------------------
// Global Plugin Functions
// ----------------------------------------------------------------------

void TSPluginInit(int argc, const char *argv[]) {
  static const char usage[] = "geoip_db [--tag=Tag_1] [--file=PATH_1] ... [--tag=TAG_N] [--file=PATH_N]";
  static const struct option longopts[] = {{const_cast<char *>("tag"), required_argument, NULL, 't'},
					   {const_cast<char *>("file"), required_argument, NULL, 'f'},
					   {NULL, 0, NULL, 0}};

  TSPluginRegistrationInfo info;
  int tag_index = 0;
  char *tag = NULL;
  char *filename = NULL;
  int x;
  struct GeoIP_DB *new_db;

  TSDebug("geoip_db","Starting plugin initialization.");

  info.plugin_name = (char *)"geoip_db";
  info.vendor_name = (char *)"Apache Software Foundation";
  info.support_email = (char *)"dev@trafficserver.apache.org";
  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[geoip_db] Plugin registration failed.");
  }

  // NULL out the GeoIP_DBs pointer array.
  for (x = 0; x < MAX_GEOIP_DB; x++) GeoIP_DBs[x] = NULL;

  // Process plugin arguments
  optind = 1;
  for ( ; tag_index < MAX_GEOIP_DB ; ) {
    switch (getopt_long(argc, (char * const *)argv, "t:f", longopts, NULL)) {
    case 't' :
      tag = optarg;
      TSDebug("geoip_db","Found  --tag is '%s'.",tag);
      break;
    case 'f' :
      filename = optarg;
      TSDebug("geoip_db","Found --file is '%s'.",filename);
      if (tag != NULL) {
	// Create a new GeoIP object using the given path to the DB file.
	new_db = (GeoIP_DB *)malloc(sizeof(GeoIP_DB));
	new_db->object = GeoIP_open(filename,GEOIP_MMAP_CACHE);
	if (new_db->object == NULL) {
	  free(new_db);
	  TSError("[geoip_db] Error: Unable to open '%s'.\n",filename);
	  exit(1);
	}
	else {
	  if (strlen(tag) > 8) {
	    TSError("[geoip_db] Error: Please limit the tag length to 8 characters.\n");
	    exit(1);
	  }
	  new_db->tag = (char *)malloc(MAX_GEOIP_DB_TAG + 1);
	  strncpy(new_db->tag,tag,MAX_GEOIP_DB_TAG);
	  new_db->tag[MAX_GEOIP_DB_TAG] = 0;
	  new_db->filename = (char *)malloc(strlen(filename)+1);
	  strcpy(new_db->filename,filename);
	  GeoIP_DBs[tag_index++] = new_db;
	}
	tag = NULL;
      }
      break;
    case -1 :
      goto init;
    default:
      TSError("[geoip_db] usage: %s", usage);
      exit(1);
    }
  }

 init:

  // Process the tagged DBs
  GeoIP_DB_Total = tag_index;
  for (x = 0 ; x < GeoIP_DB_Total; x++) {
    TSDebug("geoip_db","Created GeoIP_DB '%s' = '%s'.",
	    GeoIP_DBs[x]->tag,
	    GeoIP_DBs[x]->filename);
  }

  // Process the default DB
  GeoIP_DB_Default = GeoIP_new(GEOIP_MMAP_CACHE);
  if (!GeoIP_DB_Default) {
    printf("[geoip_db] Error: Unable to open the default DB.\n");
    exit(1);
  }

  // Test look-up with the old @Home's IP address block with the default DB.
  GeoIP_DB_Lookup("","24.1.1.1");

  TSDebug("geoip_db", "Finished plugin initialization.");
}

// ----------------------------------------------------------------------
// Remap Plugin Functions
// ----------------------------------------------------------------------

TSReturnCode TSRemapInit(TSRemapInterface *api_info, char *errbuf, int errbuf_size) {
  if (api_info->size < sizeof(TSRemapInterface)) {
    strncpy(errbuf, "[geoip_db] - Incorrect size of TSRemapInterface structure.", errbuf_size - 1);
    return TS_ERROR;
  }

  if (api_info->tsremap_version < TSREMAP_VERSION) {
    snprintf(errbuf, errbuf_size - 1, "[geoip_db] - Incorrect API version %ld.%ld.",
	     api_info->tsremap_version >> 16,
             (api_info->tsremap_version & 0xffff));
    return TS_ERROR;
  }

  TSDebug("geoip_db", "Remap plugin is successfully initialized.");
  return TS_SUCCESS; /* success */
}

TSReturnCode TSRemapNewInstance(int argc, char *argv[], void **ih, char * /* errbuf */, int /* errbuf_size */) {
  int *lookup_ptr = (int *)malloc(sizeof(int));
  int lookup = -1;

  if (argc >= 3) {
    for (int x = 0; x < GeoIP_DB_Total; x++) {
      if (strcmp(argv[2],GeoIP_DBs[x]->tag) == 0) {
	lookup = x;
      }
    }
    if (lookup == -1) {
      TSError("[geoip_db] Tag '%s' provided in remap entry is not found.",argv[2]);
    }
  }

  *lookup_ptr = lookup;
  *ih = static_cast<void *>(lookup_ptr);
  TSDebug("geoip_db","Created remap instance with tag '%s' and lookup index '%d'.",argv[2],lookup);

  return TS_SUCCESS;
}

void TSRemapDeleteInstance(void *ih) {
  int *lookup_ptr = static_cast<int *>(ih);
  int lookup = *lookup_ptr;
  free(lookup_ptr);
  TSDebug("geoip_db","Deleted remap instance with index '%d'.",lookup);
}

TSRemapStatus TSRemapDoRemap(void *ih, TSHttpTxn rh, TSRemapRequestInfo *rri) {
  int country_id = 0;
  const char *country_code;
  const char *country_name;
  uint32_t ipnum;
  int *lookup_ptr;
  int lookup;
  char cip[128];

  TSDebug("geoip_db","TSRemapDoRemap():");

  // Check for bad ih
  if (ih == NULL) {
    TSDebug("geoip_db", "No lookup configured, this is probably a plugin bug");
    return TSREMAP_NO_REMAP;
  }

  // Get the client address
  const sockaddr *addr = TSHttpTxnClientAddrGet(rh);
  switch (addr->sa_family) {
  case AF_INET:
    ipnum = ntohl(reinterpret_cast<const struct sockaddr_in *>(addr)->sin_addr.s_addr);
    inet_ntop(AF_INET, (const void *)&((struct sockaddr_in *)addr)->sin_addr,cip,sizeof(cip));
    TSDebug("geoip_db","  ipaddr = '%s'",cip);
    break;
  case AF_INET6:
    return TSREMAP_NO_REMAP;
  default:
    break;
  }

  // Do the lookup
  lookup_ptr = static_cast<int *>(ih);
  lookup = *lookup_ptr;
  if (lookup == -1) {
    country_id = GeoIP_id_by_ipnum(GeoIP_DB_Default, ipnum);
    TSDebug("geoip_db","  tag    = ''");
  }
  else {
    TSDebug("geoip_db","  tag    = '%s'",GeoIP_DBs[lookup]->tag);
    country_id = GeoIP_id_by_ipnum(GeoIP_DBs[lookup]->object, ipnum);
  }
  country_code = GeoIP_country_code[country_id];
  country_name = GeoIP_country_name[country_id];
  TSDebug("geoip_db","  RESULT = '%s' -- '%s'", country_code, country_name);

  // Put the looked-up info in the MIME header
  TSMBuffer cbuf;
  TSMLoc chdr;
  TSMLoc cloc;
  TSHttpTxnClientReqGet(rh,&cbuf,&chdr);
  if (TSMimeHdrFieldCreateNamed(cbuf, chdr, 
				"@ATS_GEOIP_DB_COUNTRY",
				sizeof("@ATS_GEOIP_DB_COUNTRY") - 1,
				&cloc) == TS_SUCCESS) {
    if (TSMimeHdrFieldValueStringInsert(cbuf, chdr, cloc, -1,
					country_code,
					sizeof(country_code) - 1) == TS_SUCCESS) {
      TSMimeHdrFieldAppend(cbuf, chdr, cloc);
    }
  }
  TSHandleMLocRelease(cbuf, chdr, cloc);

  // Work-around for ATS remap behavior, also put the original pre-remap URL in the MIME header
  TSMBuffer cbuf2;
  TSMLoc chdr2;
  TSMLoc cloc2;
  char *url;
  int url_len = 0;
  url = TSUrlStringGet(rri->requestBufp, rri->requestUrl, &url_len);
  TSHttpTxnClientReqGet(rh,&cbuf2,&chdr2);
  if (TSMimeHdrFieldCreateNamed(cbuf2, chdr2,
				"@ATS_GEOIP_DB_URL",
				sizeof("@ATS_GEOIP_DB_URL") - 1,
			        &cloc2) == TS_SUCCESS) {
    if (TSMimeHdrFieldValueStringInsert(cbuf2, chdr2, cloc2, -1,
					url,
					url_len) == TS_SUCCESS) {
      TSMimeHdrFieldAppend(cbuf2,chdr2,cloc2);
    }
  }
  TSHandleMLocRelease(cbuf2, chdr2, cloc2);
  TSfree(url);

  // Exit without remapping anything inside the plugin.
  return TSREMAP_NO_REMAP;
}
