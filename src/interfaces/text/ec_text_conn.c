/*
    ettercap -- diplay the connection list 

    Copyright (C) ALoR & NaGA

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*/

#include <ec.h>
#include <ec_threads.h>
#include <ec_interfaces.h>
#include <ec_conntrack.h>
#include <ec_inet.h>
#include <ec_proto.h>

/* globals */

/* proto */

void text_connections();
void text_pinger(int ping);

/*******************************************/

void text_connections()
{   
   void *list;
   char *desc;
   
   SAFE_CALLOC(desc, 100, sizeof(char));

   /* retrieve the first element */
   list = conntrack_print(0, NULL, NULL, 0);
   
   fprintf(stdout, "\nConnections list:\n\n");
  
   /* walk the connection list */
   while(list) {
      /* get the next element */
      list = conntrack_print(+1, list, &desc, 99);
      fprintf(stdout, "%s\n", desc);
   }

   fprintf(stdout, "\n");

   SAFE_FREE(desc);
}

/*******************************************/

void text_pinger(int ping)
{
   void *list;
   char *desc, *tmpdesc;

   SAFE_CALLOC(desc, 200, sizeof(char));

   /* retrieve the first element */
   list = pingtrack_print(0, NULL, NULL, 0, ping);

   fprintf(stdout, "\nActive connection list:\n\n");

   /* walk the connection list */
   while(list) {
      /* get the next element */
	  tmpdesc = desc;
      list = pingtrack_print(+1, list, &tmpdesc, 199, ping);
      if ( tmpdesc != NULL )
         fprintf(stdout, "%s\n", tmpdesc);
   }

   fprintf(stdout, "\n");

   SAFE_FREE(desc);
}

/* EOF */

// vim:ts=3:expandtab

