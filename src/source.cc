/*
 * This file is part of Build Gear.
 *
 * Copyright (c) 2011-2013  Martin Lund
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include "config.h"
#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <linux/limits.h>
#include <ncurses.h>
#include <curl/curl.h>
#include "buildgear/config.h"
#include "buildgear/options.h"
#include "buildgear/filesystem.h"
#include "buildgear/buildfiles.h"
#include "buildgear/dependency.h"
#include "buildgear/source.h"
#include "buildgear/download.h"
#include "buildgear/cursor.h"
#include "buildgear/log.h"

extern CLog Log;

string bytes2str(double bytes)
{
   int i;
   ostringstream result;
   string unit[] = {"B", "kB", "MB", "GB", "TB"};

   for (i=0;bytes > 1000;i++)
   {
      bytes /= 1000;
   }

   result << setprecision(2) << fixed << bytes << unit[i];

   return result.str();
}

string seconds2str(double seconds)
{
   ostringstream result;
   int min = 0;
   int hr  = 0;
   int day = 0;

   while (seconds > 60)
   {
      seconds -= 60;
      min++;

      if (min == 60)
      {
         min = 0;
         hr++;
      }

      if (hr == 24)
      {
         hr = 0;
         day++;
      }
   }

   if (day > 0)
      result << " " << day << " days";
   if (hr > 0)
      result << " " << hr << " hr";
   if (min > 0)
      result << " " << min << " min";
      result << " " << setprecision(2) << fixed << seconds << " sec";

   return result.str();
}

int CSource::Remote(string item)
{
   int i;
   curl_version_info_data *curl_info;

   curl_info = curl_version_info(CURLVERSION_NOW);

   for (i=0; curl_info->protocols[i] != NULL; i++)
   {
      if (item.find(string(curl_info->protocols[i]) + "://") != item.npos)
         return true;
   }

   return false;
}

void CSource::Download(list<CBuildFile*> *buildfiles, string source_dir)
{
   CDownload Download;

   list<CBuildFile*>::iterator it;
   string command;

   int active_downloads = -1;
   CURLMsg *msg;
   int nMsg;
   int i;

   int maxfd;
   fd_set read, write, exc;
   struct timeval tv;
   long timeout, response;
   double total_time;
   double speed;

   ostringstream status;

   /* Make sure that source dir exists */
   CreateDirectory(source_dir);

   /* Initialize the multi curl element */
   curl_global_init(CURL_GLOBAL_ALL);
   Download.curlm = curl_multi_init();

   if (stoi(Config.bg_config[CONFIG_KEY_DOWNLOAD_CONNECTIONS])) {
      curl_multi_setopt(Download.curlm, CURLMOPT_MAXCONNECTS,
            stoi(Config.bg_config[CONFIG_KEY_DOWNLOAD_CONNECTIONS]));
   }

   /* Traverse buildfiles download list */
   for (it=buildfiles->begin(); it!=buildfiles->end(); it++)
   {
      istringstream iss((*it)->source);
      string item;

      // For each source item
      while ( getline(iss, item, ' ') )
      {
         // Download item if it is a remote URL
         if (CSource::Remote(item))
            new CDownloadItem(item, source_dir, &Download);
      }
   }

   // Print number of files to be downloaded
   if (Download.pending_downloads.size() > 0)
   {
      cout << "     (" << Download.pending_downloads.size() << " files)" << flush;
      status.str("");
      status << "======> Download\n\n";
      status << "Downloading " << Download.pending_downloads.size() << " files.\n\n";
      Log.print(status.str());
   }

   // Add download_connections downloads to multi stack
   for (i=0;i<stoi(Config.bg_config[CONFIG_KEY_DOWNLOAD_CONNECTIONS]);i++)
   {
      // Stop if no more downloads are pending
      if (Download.pending_downloads.size() == 0)
         break;

      CDownloadItem *item = Download.pending_downloads.front();
      Download.pending_downloads.pop_front();

      Download.lock();

      // item->print_progress(); // Don't print initial status

      Download.unlock();

      Download.active_downloads.push_back(item);
      curl_multi_add_handle(Download.curlm, item->curl);
   }

   while (active_downloads)
   {
      curl_multi_perform(Download.curlm, &active_downloads);
      if (active_downloads) {
         FD_ZERO(&read);
         FD_ZERO(&write);
         FD_ZERO(&exc);

         if (curl_multi_fdset(Download.curlm, &read, &write, &exc, &maxfd))
         {
            cout << "Error: curl_multi_fdset" << endl << flush;
            exit(EXIT_FAILURE);
         }

         if (curl_multi_timeout(Download.curlm, &timeout))
         {
            cout << "Error: curl_multi_timeout" << endl << flush;
            exit(EXIT_FAILURE);
         }

         if (timeout == -1)
            timeout = 100;

         if (maxfd == -1) {
            sleep(timeout / 1000);
         } else {
            tv.tv_sec = timeout / 1000;
            tv.tv_usec = (timeout % 1000) * 1000;

            if (0 > select(maxfd+1, &read, &write, &exc, &tv))
            {
               cout << "Errror: select" << endl << flush;
               exit(EXIT_FAILURE);
            }
         }
      }

      while ((msg = curl_multi_info_read(Download.curlm, &nMsg)))
      {
         if (msg->msg == CURLMSG_DONE)
         {
            CDownloadItem *item;
            curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &item);
            curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE, &response);

            // The easy handle did not return CURLE_OK
            if (msg->data.result != CURLE_OK)
            {
               char *used_url;
               curl_easy_getinfo(msg->easy_handle, CURLINFO_EFFECTIVE_URL, &used_url);

               // The server does not support resume
               if (msg->data.result == CURLE_RANGE_ERROR)
               {
                  curl_multi_remove_handle(Download.curlm, msg->easy_handle);

                  // If the temp file exists we delete it
                  if (FileExist(item->source_dir + "/" + item->filename + ".part"))
                  {
                    string command;
                    command = "rm -f " + item->source_dir + "/"
                              + item->filename + ".part";

                    if (system(command.c_str()) < 0)
                       perror("error");
                  }

                  curl_easy_setopt(item->curl, CURLOPT_RESUME_FROM, 0);
                  item->start_offset = 0;

                  // Start transfer again from beginning of file
                  curl_multi_add_handle(Download.curlm, item->curl);

                  // Make sure loop does not end
                  active_downloads++;
                  continue;
               }

               long response_code;
               curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE, &response_code);

               // Handle non authorized access
               if (response_code == 401 && item->tries > 1)
               {
                  string user, pass;

                  item->status = "Authorization is required";

                  Download.lock();

                  // Print the download that requires crendentials
                  Cursor.line_up(Cursor.get_ypos());
                  Cursor.clear_below();
                  item->print_progress();

                  cout << endl << "Username: " << flush;

                  // Enable echo to let the user see the username
                  Cursor.enable_echo();
                  Cursor.show();
                  getline (cin, user);

                  // Disable echo for the password
                  Cursor.disable_echo();
                  cout << "Password: " << flush;
                  getline (cin, pass);
                  Cursor.hide();
                  cout << endl;

                  // Ensure that the login lines will be overwritten
                  Cursor.ypos_add(3);

                  Download.unlock();

                  // Set user and pass on the handle
                  curl_easy_setopt (msg->easy_handle, CURLOPT_USERNAME, user.c_str());
                  curl_easy_setopt (msg->easy_handle, CURLOPT_PASSWORD, pass.c_str());
               }

               if (item->tries-- > 0)
               {
                  // Restart download by readding the easy handle
                  curl_multi_remove_handle(Download.curlm, msg->easy_handle);
                  curl_multi_add_handle(Download.curlm, msg->easy_handle);

                  // Make sure loop does not end
                  active_downloads++;

                  // Clear debug log
                  item->debug.clear();
                  continue;
               }

               if (!item->alternative_url)
               {
                  if (item->mirror_url == "")
                  {
                     curl_multi_remove_handle(Download.curlm, msg->easy_handle);
                     status.str("");
                     status << "Error " << response_code <<" (";
                     status << curl_easy_strerror(msg->data.result) << ")";
                     item->status = status.str();
                     item->downloaded = -1;
                     Log.print(status.str() + '\n');

                     Download.lock();

                     Cursor.line_up(Cursor.get_ypos());
                     item->print_progress();

                     // Print debug if not a HTTP error
                     if (response_code == 0)
                     {
                        Cursor.clear_below();
                        cout << endl << item->debug;
                     }

                     Cursor.ypos_add(-DOWNLOAD_LINE_SIZE);

                     Download.error = true;
                     Download.active_downloads.remove(item);

                     Download.unlock();

                     if (Download.activate_download())
                     {
                        // Prevent loop from ending
                        active_downloads++;
                     }
                     continue;
                  }

                  CURL *tmp_handle;

                  curl_multi_remove_handle(Download.curlm, msg->easy_handle);

                  // Duplicate handle to keep configuration, but reset state info
                  tmp_handle = curl_easy_duphandle (msg->easy_handle);
                  curl_easy_cleanup (msg->easy_handle);
                  item->curl = tmp_handle;

                  status.str("");
                  status << "Error " << response_code << " (";
                  status << curl_easy_strerror(msg->data.result) << ") trying alternative URL..";
                  item->status = status.str();
                  item->downloaded = -1;
                  Log.print(status.str() + '\n');

                  Download.lock();

                  Cursor.line_up(Cursor.get_ypos());
                  item->print_progress();

                  // Print debug if not HTTP error
                  if (response_code == 0)
                  {
                     Cursor.clear_below();
                     cout << endl << item->debug;
                  }

                  Cursor.ypos_add(-DOWNLOAD_LINE_SIZE);

                  Download.unlock();

                  item->alternative_url = true;
                  item->status = "Requesting file (Alternative)..";

                  item->tries = stoi(Config.bg_config[CONFIG_KEY_DOWNLOAD_RETRY]);

                  curl_easy_setopt(item->curl, CURLOPT_URL, item->mirror_url.c_str());

                  curl_multi_add_handle(Download.curlm, item->curl);

                  // Prevent while loop from stopping prematurely
                  active_downloads++;
                  continue;
               } else
               {
                  status.str("");
                  status << "Error " << response_code << " (";
                  status << curl_easy_strerror(msg->data.result) << ")";
                  item->status = status.str();
                  item->downloaded = -1;
                  Log.print(status.str() + '\n');

                  Download.lock();

                  Cursor.line_up(Cursor.get_ypos());
                  item->print_progress();

                  // Print debug if not a HTTP error
                  if (response_code == 0)
                  {
                     Cursor.clear_below();
                     cout << endl << item->debug;
                  }

                  Cursor.ypos_add(-DOWNLOAD_LINE_SIZE);

                  Download.error = true;
                  Download.active_downloads.remove(item);

                  Download.unlock();

                  if (Download.activate_download())
                  {
                     // Prevent loop from ending
                     active_downloads++;
                  }
                  continue;
               }
            }

            if (item->file.stream)
               fclose(item->file.stream);

            if (FileExist(item->source_dir + "/" + item->filename + ".part"))
            {
               Move(item->source_dir + "/" + item->filename + ".part",
                     item->source_dir + "/" + item->filename);

               // We force update of downloaded/total
               curl_easy_getinfo(item->curl, CURLINFO_SIZE_DOWNLOAD, &item->downloaded);
               curl_easy_getinfo(item->curl, CURLINFO_TOTAL_TIME, &total_time);
               curl_easy_getinfo(item->curl, CURLINFO_SPEED_DOWNLOAD, &speed);

               status.str("");
               status << "Download OK (" << bytes2str(item->downloaded) << " in" << seconds2str(total_time)
                    << " at " << bytes2str(speed) << "/s)";
               item->status = status.str();
               item->downloaded = -1;

               // Print download status to log
               status.str("");
               status << "Download ";
               if (item->alternative_url)
                  status << item->mirror_url;
               else
                  status << item->url;
               status << '\n' << item->status << "\n\n";
               Log.print(status.str());

               Download.lock();

               // Move cursor to first active element
               Cursor.line_up(Cursor.get_ypos());

               item->print_progress();

               // Remove the download
               Download.active_downloads.remove(item);

               // Dont overwrite the last output
               Cursor.ypos_add(-DOWNLOAD_LINE_SIZE);

               Download.unlock();

               Download.update_progress();

            } else {
               status.str("");
               status << "Error: " << item->source_dir + "/" + item->filename + ".part" << " not found" << endl << flush;
               cout << status.str();
               Log.print(status.str());
               exit(EXIT_FAILURE);
            }

            curl_multi_remove_handle(Download.curlm, msg->easy_handle);
            curl_easy_cleanup(msg->easy_handle);

            // Check if there are more downloads pending
            if (Download.activate_download())
            {
               // Prevent while loop to end prematurely
               active_downloads++;
            }
         } else {
            status.str("");
            status << "Error: CURLMsg (" << msg->msg << ")" << endl << flush;
            cout << status.str();
            Log.print(status.str());
            exit(EXIT_FAILURE);
         }
      }
   }
   curl_multi_cleanup(Download.curlm);
   curl_global_cleanup();

   // Reset to avoid extra newlines on exit
   Cursor.reset_ymaxpos();

   // Beautify download finish output
   if (!Download.first)
      cout << endl;

   if (Download.error)
   {
      status.str("");
      status << "Error: Could not download all sources - see download errors above." << endl;
      cout << status.str();
      Log.print(status.str());
      exit(EXIT_FAILURE);
   }
}
