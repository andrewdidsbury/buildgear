/*
 * Copyright (C) 2011-2012  Martin Lund
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"
#include <iostream>
#include <sstream>
#include <string>
#include <stdexcept>
#include <list>
#include <stdio.h>
#include <errno.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "buildgear/config.h"
#include "buildgear/configfile.h"

void CConfigFile::Parse(string filename)
{
      FILE *fp;
      char line_buffer[PATH_MAX];
      string command =  "bash --norc --noprofile -O extglob -c 'source " + filename + " 2> /dev/null";
      
      if (filename != BUILD_FILES_CONFIG)
         command += "; echo source_dir=$source_dir \
                     ; echo download_mirror=$download_mirror \
                     ; echo download_mirror_first=$download_mirror_first \
                     ; echo download_timeout=$download_timeout \
                     ; echo download_retry=$download_retry \
                     ; echo required_version=$required_version \
                     ; echo default_name_prefix=$default_name_prefix \
                     ; echo parallel_builds=$parallel_builds \
                     '";
      else
         command += "; echo cross_depends=${CROSS_DEPENDS[@]} \
                     ; echo build=$BUILD \
                     ; echo host=$HOST \
                     '";
      
      fp = popen(command.c_str(), "r");
      if (fp == NULL)
         throw std::runtime_error(strerror(errno));

      while (fgets(line_buffer, PATH_MAX, fp) != NULL)
      {
         // Parse key=value pairs
         string line(line_buffer);
         string key, value;
         size_t pos = line.find_first_of('=');
	
         key=line.substr(0, pos);
         value=line.substr(pos+1);

         stripChar(value, '\n');

         if (value != "")
         {
            if (filename != BUILD_FILES_CONFIG)
            {
               // ~/.buildgearconfig, .buildgear/config :
               if (key == CONFIG_KEY_DEFAULT_NAME_PREFIX)
                  Config.default_name_prefix = value;
               if (key == CONFIG_KEY_SOURCE_DIR)
                  Config.source_dir = value;
               if (key == CONFIG_KEY_DOWNLOAD_TIMEOUT)
                  Config.download_timeout = atoi(value.c_str());
               if (key == CONFIG_KEY_DOWNLOAD_RETRY)
                  Config.download_retry = atoi(value.c_str());
               if (key == CONFIG_KEY_DOWNLOAD_MIRROR)
                  Config.download_mirror = value;
               if (key == CONFIG_KEY_DOWNLOAD_MIRROR_FIRST)
                  Config.download_mirror_first = value;
// Temporarily disabled support for parallel builds
//               if (key == CONFIG_KEY_PARALLEL_BUILDS)
//                  Config.parallel_builds = atoi(value.c_str());
            }
            else
            {
               // buildfiles/config :
               if (key == CONFIG_KEY_CROSS_DEPENDS)
                  Config.cross_depends = value;
               if (key == CONFIG_KEY_BUILD)
                  Config.build_system = value;
               if (key == CONFIG_KEY_HOST)
                  Config.host_system = value;
            }
         }
      }
      pclose(fp);
}
