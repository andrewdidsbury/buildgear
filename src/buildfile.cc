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
#include <limits.h>
#include "buildgear/config.h"
#include "buildgear/buildfile.h"
#include "buildgear/filesystem.h"
#include "buildgear/utility.h"
#include "buildgear/log.h"
#include "buildgear/cursor.h"

CBuildFile::CBuildFile(string filename)
{
   CBuildFile::filename = filename;
   CBuildFile::build = false;
   CBuildFile::have_pkg = false;
   CBuildFile::visited = false;
   CBuildFile::depth = 0;
   CBuildFile::description = "";
   CBuildFile::url = "";
   CBuildFile::license = "";
   CBuildFile::options.buildlock = false;
   CBuildFile::options.nostrip = "no";
}

string CBuildFile::GetLocation()
{
   size_t pos;
   pos = filename.find_last_of('/');
   return filename.substr(0,pos + 1);
}

void CBuildFile::Show(void)
{
   string arguments;
   string command;

   arguments += " --BG_SHORT_NAME '" + this->short_name + "'";
   arguments += " --BG_BUILD_FILE '" + filename + "'";
   arguments += " --BG_ACTION 'read'";
   arguments += " --BG_BUILD_FILES_CONFIG '" BUILD_FILES_CONFIG "'";
   arguments += " --BG_OUTPUT_DIR '" OUTPUT_DIR "'";
   arguments += " --BG_PACKAGE_DIR '" PACKAGE_DIR "'";
   arguments += " --BG_BUILD_TYPE '" + type + "'";
   arguments += " --BG_SYSROOT_DIR '" SYSROOT_DIR "'";
   arguments += " --BG_WORK_DIR '" WORK_DIR "'";
   arguments += " --BG_BUILD '" + Config.bf_config[CONFIG_KEY_BUILD] + "'";
   arguments += " --BG_HOST '" + Config.bf_config[CONFIG_KEY_HOST] + "'";
   arguments += " --BG_SOURCE_DIR '" + Config.bg_config[CONFIG_KEY_SOURCE_DIR] + "'";

   command = SCRIPT " " + arguments;
   command = "bash --norc --noprofile -O extglob -c 'setsid " + command + " 2>&1' 2>&1";

   cout << endl;

   if (system(command.c_str()) != 0)
   {
      cout << "\nError: Could not show buildfile for '" << name << "'\n";
      cout << strerror(errno) << endl;
      exit(EXIT_FAILURE);
   }

   cout << endl;
}

bool CBuildFile::SourceChecksumMismatch(void)
{
   string arguments;
   string command;
   string source_checksum_file;
   int status;

   if (this->type == "native")
   {
       source_checksum_file = SOURCE_CHECKSUM_NATIVE_DIR "/" + this->short_name + ".sha256sum";
   }
   else
   {
      source_checksum_file = SOURCE_CHECKSUM_CROSS_DIR "/" + this->short_name + ".sha256sum";
   }

   arguments += " --BG_SHORT_NAME '" + this->short_name + "'";
   arguments += " --BG_BUILD_FILE '" + filename + "'";
   arguments += " --BG_ACTION 'verify_source_checksum'";
   arguments += " --BG_BUILD_FILES_CONFIG '" BUILD_FILES_CONFIG "'";
   arguments += " --BG_OUTPUT_DIR '" OUTPUT_DIR "'";
   arguments += " --BG_PACKAGE_DIR '" PACKAGE_DIR "'";
   arguments += " --BG_BUILD_TYPE '" + type + "'";
   arguments += " --BG_SYSROOT_DIR '" SYSROOT_DIR "'";
   arguments += " --BG_WORK_DIR '" WORK_DIR "'";
   arguments += " --BG_BUILD '" + Config.bf_config[CONFIG_KEY_BUILD] + "'";
   arguments += " --BG_HOST '" + Config.bf_config[CONFIG_KEY_HOST] + "'";
   arguments += " --BG_SOURCE_DIR '" + Config.bg_config[CONFIG_KEY_SOURCE_DIR] + "'";
   arguments += " --BG_SOURCE_SHA256SUM '" + source_checksum_file + "'";

   command = SCRIPT " " + arguments;
   command = "bash --norc --noprofile -O extglob -c 'setsid " + command + " 2>&1' 2>&1";

   status = system(command.c_str());
   if (status == -1)
   {
      cout << "\nError: Could not verify buildfile checksum for '" << name << "'\n";
      cout << strerror(errno) << endl;
      exit(EXIT_FAILURE);
   }

   status = WEXITSTATUS(status);
   if (status == 1)
      return true;

   // No checksum mismatch
   return false;
}

bool CBuildFile::BuildfileChecksumMismatch(void)
{
   string arguments;
   string command;
   string buildfile_checksum_file;
   int status;

   if (this->type == "native")
   {   
      buildfile_checksum_file = BUILDFILE_CHECKSUM_NATIVE_DIR "/" + this->short_name + ".sha256sum";
   }
   else
   {
      buildfile_checksum_file = BUILDFILE_CHECKSUM_CROSS_DIR "/" + this->short_name + ".sha256sum";
   }

   arguments += " --BG_SHORT_NAME '" + this->short_name + "'";
   arguments += " --BG_BUILD_FILE '" + filename + "'";
   arguments += " --BG_ACTION 'verify_buildfile_checksum'";
   arguments += " --BG_BUILD_FILES_CONFIG '" BUILD_FILES_CONFIG "'";
   arguments += " --BG_OUTPUT_DIR '" OUTPUT_DIR "'";
   arguments += " --BG_PACKAGE_DIR '" PACKAGE_DIR "'";
   arguments += " --BG_BUILD_TYPE '" + type + "'";
   arguments += " --BG_SYSROOT_DIR '" SYSROOT_DIR "'";
   arguments += " --BG_WORK_DIR '" WORK_DIR "'";
   arguments += " --BG_BUILD '" + Config.bf_config[CONFIG_KEY_BUILD] + "'";
   arguments += " --BG_HOST '" + Config.bf_config[CONFIG_KEY_HOST] + "'";
   arguments += " --BG_SOURCE_DIR '" + Config.bg_config[CONFIG_KEY_SOURCE_DIR] + "'";
   arguments += " --BG_BUILDFILE_SHA256SUM '" + buildfile_checksum_file + "'";

   command = SCRIPT " " + arguments;
   command = "bash --norc --noprofile -O extglob -c 'setsid " + command + " 2>&1' 2>&1";

   status = system(command.c_str());
   if (status == -1)
   {
      cout << "\nError: Could not verify buildfile checksum for '" << name << "'\n";
      cout << strerror(errno) << endl;
      exit(EXIT_FAILURE);
   }

   status = WEXITSTATUS(status);
   if (status == 1)
      return true;

   // No checksum mismatch
   return false;
}

string CBuildFile::GetSourceChecksum(void)
{
  if ( !source_checksum.empty() )
  {
     return source_checksum;
  }

  string arguments;
  string command;

  arguments += " --BG_SHORT_NAME '" + this->short_name + "'";
  arguments += " --BG_BUILD_FILE '" + filename + "'";
  arguments += " --BG_ACTION 'print_source_checksum'";
  arguments += " --BG_BUILD_FILES_CONFIG '" BUILD_FILES_CONFIG "'";
  arguments += " --BG_OUTPUT_DIR '" OUTPUT_DIR "'";
  arguments += " --BG_PACKAGE_DIR '" PACKAGE_DIR "'";
  arguments += " --BG_BUILD_TYPE '" + type + "'";
  arguments += " --BG_SYSROOT_DIR '" SYSROOT_DIR "'";
  arguments += " --BG_WORK_DIR '" WORK_DIR "'";
  arguments += " --BG_BUILD '" + Config.bf_config[CONFIG_KEY_BUILD] + "'";
  arguments += " --BG_HOST '" + Config.bf_config[CONFIG_KEY_HOST] + "'";
  arguments += " --BG_SOURCE_DIR '" + Config.bg_config[CONFIG_KEY_SOURCE_DIR] + "'";

  command = SCRIPT " " + arguments;
  command = "bash --norc --noprofile -O extglob -c 'setsid " + command + " 2>&1' 2>&1";

  char buffer[128];
  std::string result = "";
  FILE* pipe = popen(command.c_str(), "r");
  if (!pipe) throw std::runtime_error("popen() failed!");
  try 
  {
    // Read the first line, remove the newline
    if (fgets(buffer, sizeof buffer, pipe) != NULL) 
    {
      size_t len = strlen(buffer);
      if ( len > 0 && buffer[len-1] == '\n' ) buffer[len-1] = 0;
      result += buffer;
    }
  } 
  catch (...) 
  {
  }
  pclose(pipe);
  source_checksum = result;
  return result;
}

string CBuildFile::GetBuildfileChecksum(void)
{
  if ( !buildfile_checksum.empty() )
  {
     return buildfile_checksum;
  }
  string arguments;
  string command;

  arguments += " --BG_SHORT_NAME '" + this->short_name + "'";
  arguments += " --BG_BUILD_FILE '" + filename + "'";
  arguments += " --BG_ACTION 'print_buildfile_checksum'";
  arguments += " --BG_BUILD_FILES_CONFIG '" BUILD_FILES_CONFIG "'";
  arguments += " --BG_OUTPUT_DIR '" OUTPUT_DIR "'";
  arguments += " --BG_PACKAGE_DIR '" PACKAGE_DIR "'";
  arguments += " --BG_BUILD_TYPE '" + type + "'";
  arguments += " --BG_SYSROOT_DIR '" SYSROOT_DIR "'";
  arguments += " --BG_WORK_DIR '" WORK_DIR "'";
  arguments += " --BG_BUILD '" + Config.bf_config[CONFIG_KEY_BUILD] + "'";
  arguments += " --BG_HOST '" + Config.bf_config[CONFIG_KEY_HOST] + "'";
  arguments += " --BG_SOURCE_DIR '" + Config.bg_config[CONFIG_KEY_SOURCE_DIR] + "'";

  command = SCRIPT " " + arguments;
  command = "bash --norc --noprofile -O extglob -c 'setsid " + command + " 2>&1' 2>&1";

  char buffer[128];
  std::string result = "";
  FILE* pipe = popen(command.c_str(), "r");
  if (!pipe) throw std::runtime_error("popen() failed!");
  try 
  {
    // Read the first line, remove the newline
    if (fgets(buffer, sizeof buffer, pipe) != NULL) 
    {
      size_t len = strlen(buffer);
      if ( len > 0 && buffer[len-1] == '\n' ) buffer[len-1] = 0;
      result += buffer;
    }
  } 
  catch (...) 
  {
  }
  pclose(pipe);
  buildfile_checksum = result;
  return result;
}

void CBuildFile::GetDepChecksum( CBuildFile * build, stringstream & ss )
{
   for (auto it = build->dependency.begin(); it != build->dependency.end(); ++it)
   {
      GetDepChecksum(*it, ss);
      
      ss << (*it)->short_name << " " << (*it)->source_checksum << "-" << (*it)->buildfile_checksum << std::endl;
   }
}

string CBuildFile::GetDepChecksum(void)
{
   if ( !dep_checksum.empty() )
   {
     return dep_checksum;
   }

   stringstream ss;
   GetDepChecksum( this, ss );
   dep_checksum = ss.str();

   //printf("## %s has dep checksum file '%s'", short_name.c_str(), dep_checksum.c_str());

   return dep_checksum;
}

string CBuildFile::GetChecksum(void)
{
   if ( !checksum.empty() )
   {
      return checksum;
   }

   string cmd = "echo -e \"" + GetSourceChecksum() + GetBuildfileChecksum() + GetDepChecksum() + "\" | sha256sum | awk '{print $1}'";
   
   char buffer[128];
   std::string result = "";
   FILE* pipe = popen(cmd.c_str(), "r");
   if (!pipe) throw std::runtime_error("popen() failed!");
   try 
   {
      // Read the first line, remove the newline
      if (fgets(buffer, sizeof buffer, pipe) != NULL) 
      {
         size_t len = strlen(buffer);
         if ( len > 0 && buffer[len-1] == '\n' ) buffer[len-1] = 0;
         result = buffer;
      }
   } 
   catch (...) 
   {
   }
   pclose(pipe);

   checksum = result;
   //printf("## %s has checksum %s\n", short_name.c_str(), checksum.c_str() );   
   return checksum;
}

void CBuildFile::Parse(void)
{
   FILE *fp;
   char line_buffer[PATH_MAX];
   size_t pos;
   string fifo_name;
   string layer_name;
   string command =
      "bash --norc --noprofile -O extglob -c 'source " +
       (string) BUILD_FILES_CONFIG + " 2>/dev/null \
       ; echo config_return=$? \
       ; source " + filename + " 2>/dev/null \
       ; echo build_return=$? \
       ; echo name=$name \
       ; echo version=$version \
       ; echo release=$release \
       ; echo source=${source[@]} \
       ; echo depends=${depends[@]} \
       ; echo package_manager=${package_manager[@]} \
       ; echo options=${options[@]} \
       ; echo layer=$layer \
       ; typeset -F build &> /dev/null && echo build_function=yes || echo build_function=no \
       ; typeset -F check &> /dev/null && echo check_function=yes || echo check_function=no'";

   // Open buildfile for reading
   fp = popen(command.c_str(), "r");
   if (fp == NULL)
      throw std::runtime_error(strerror(errno));

   // Assign name and type based on filename
   pos = filename.rfind("buildfiles/cross/");
   if (pos != filename.npos)
      type = "cross";
   else
   {
      pos = filename.rfind("buildfiles/native/");
      type = "native";
   }

   if (pos == filename.npos)
   {
      cout << "Error: " << filename << " is invalid." << endl;
      exit(EXIT_FAILURE);
   }

   name = filename.substr(pos);
   pos = name.rfind("/Buildfile");
   if (pos == filename.npos)
   {
      cout << "Error: " << filename << " is invalid." << endl;
      exit(EXIT_FAILURE);
   }

   // Parse Buildfile variables
   while (fgets(line_buffer, PATH_MAX, fp) != NULL)
   {
      // Parse key=value pairs
      string line(line_buffer);
      string key, value;
      size_t pos = line.find_first_of('=');

      key=line.substr(0, pos);
      value=line.substr(pos+1);

      stripChar(value, '\n');

      // Required keys (FIXME: add check for empty values)
      if (key == KEY_NAME)
         short_name = value;
      if (key == KEY_VERSION)
         version = value;
      if (key == KEY_RELEASE)
         release = value;
      if (key == KEY_CONFIG_RETURN)
      {
         if (stoi(value) != 0)
         {
            string command;
            int dummy;

            command = "source " BUILD_FILES_CONFIG;
            cout << endl << endl << "Error parsing " << BUILD_FILES_CONFIG  << endl;

            // Source the file again without redirecting the error out
            dummy = system(command.c_str());
            cout << endl;
            exit(EXIT_FAILURE);
         }
      }
      if (key == KEY_BUILD_RETURN)
      {
         if (stoi(value) != 0)
         {
            string command;
            int dummy;

            command = "source " + filename;
            cout << endl << endl << "Error parsing " << filename << endl;

            // Source the file again without redirecting the error out
            dummy = system(command.c_str());
            cout << endl;
            exit(EXIT_FAILURE);
         }
      }

      // Optional keys
      if (key == KEY_SOURCE)
         source = value;
      if (key == KEY_DEPENDS)
         depends = value;
      if (key == KEY_PACKAGE_MANAGER)
         package_manager = value;
      if (key == KEY_BUILD_FUNCTION)
         build_function = value;
      if (key == KEY_CHECK_FUNCTION)
         check_function = value;
      if (key == KEY_OPTIONS_)
      {
          // Parse options array

          // Check for "buildlock"
          if (value.find("buildlock") < value.length())
              options.buildlock = true;

          // Check for "nostrip"
          if (value.find("nostrip") < value.length())
              options.nostrip = "yes";

      }
      if (key == KEY_LAYER)
         layer_name = value;
   }
   pclose(fp);

   // Assign name based on type and name variable
   name = type + "/" + short_name;

   // Set control fifo name
   fifo_name = TEMP(type + "-" + short_name + ".fifo");
   control_fifo = new char [fifo_name.length() + 1];
   strcpy(control_fifo, fifo_name.c_str());

   // By default the "default" layer is assigned
   layer = DEFAULT_LAYER_NAME;

   // Assign layer based on layer variable (if present, 1st priority)
   if (!layer_name.empty())
   {
      // Check if layer is defined in master config
      if (Config.bf_config[CONFIG_KEY_LAYERS].find(layer_name) == string::npos
          && layer_name != string(DEFAULT_LAYER_NAME))
      {
         // No matching layer found
      } else
         layer = layer_name;
   } else
   {
      // Assign layer based on path location (if match, 2nd priority)
      string layer_token;
      istringstream is (Config.bf_config[CONFIG_KEY_LAYERS]);
      while ( is.good() )
      {
         is >> layer_token;

         if (layer_token != DEFAULT_LAYER_NAME)
         {
            size_t pos;
            string layer_path;

            if (type == "cross")
            {
               layer_path = "buildfiles/cross/cross-" + layer_token + "/";
               pos = filename.rfind(layer_path);
               if (pos != filename.npos)
                  layer = layer_token;
            } else
            {
               layer_path = "buildfiles/native/native-" + layer_token + "/";
               pos = filename.rfind(layer_path);
               if (pos != filename.npos)
                  layer = layer_token;
            }
         }
      }
   }

   // In manifest mode, also parse description, URL, and license
   if (Config.manifest_plain_text || Config.manifest_xml)
   {
      ifstream input_file(filename);

      if ( input_file.is_open() )
      {
         string line;
         string value;

         while ( getline ( input_file, line ) )
         {
            string::size_type i;

            i = line.find_first_not_of ( " \t\n\v" );

            if ( i != string::npos && line[i] == '#' )
            {
               // Parse Description from line
               i = line.find("Description:");

               if (i != string::npos)
               {
                  value = line.substr(i+12);
                  i = value.find_first_not_of(" ");
                  if (i != string::npos)
                     description = value.substr(i);
               }

               // Parse URL from line
               i = line.find("URL:");

               if (i != string::npos)
               {
                  value = line.substr(i+4);
                  i = value.find_first_not_of(" ");
                  if (i != string::npos)
                     url = value.substr(i);
               }

               // Parse License from line
               i = line.find("License:");

               if (i != string::npos)
               {
                  value = line.substr(i+8);
                  i = value.find_first_not_of(" ");
                  if (i != string::npos)
                     license = value.substr(i);
               }
            }
            else
               continue;
         }
      }
      input_file.close();
   }
}
