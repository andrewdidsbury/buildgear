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
#include <iostream>
#include <sstream>
#include <vector>
#include <thread>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <linux/limits.h>
#include <semaphore.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include "buildgear/config.h"
#include "buildgear/options.h"
#include "buildgear/filesystem.h"
#include "buildgear/buildfiles.h"
#include "buildgear/dependency.h"
#include "buildgear/source.h"
#include "buildgear/buildmanager.h"
#include "buildgear/download.h"
#include "buildgear/log.h"
#include "buildgear/cursor.h"
#include <chrono>

sem_t build_semaphore;
pthread_mutex_t add_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t active_builds_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t active_adds_mutex = PTHREAD_MUTEX_INITIALIZER;
CBuildFile *last_build;

std::string beautify_duration(std::chrono::seconds input_seconds)
{
    using namespace std::chrono;
    typedef duration<int, std::ratio<86400>> days;
    auto d = duration_cast<days>(input_seconds);
    input_seconds -= d;
    auto h = duration_cast<hours>(input_seconds);
    input_seconds -= h;
    auto m = duration_cast<minutes>(input_seconds);
    input_seconds -= m;
    auto s = duration_cast<seconds>(input_seconds);

    auto dc = d.count();
    auto hc = h.count();
    auto mc = m.count();
    auto sc = s.count();

    std::stringstream ss;
    ss.fill('0');
    if (dc) {
        ss << d.count() << " days ";
    }
    if (dc || hc) {
        ss << h.count() << " hrs ";
    }
    if (dc || hc || mc) {
        ss << m.count() << " mins ";
    }
    ss << s.count() << " secs";
    
    return ss.str();
}

class CBuildThread : CBuildManager
{
   public:
      CBuildThread(CBuildFile *buildfile);
      void operator()();
      void Start(void);
      void Join(void);
   private:
      thread *buildthread;
      CBuildFile *buildfile;
};

CBuildThread::CBuildThread(CBuildFile *buildfile)
{
   this->buildfile = buildfile;
}

void CBuildThread::operator()()
{
   // Semaphore is released by Do("build")
   sem_wait(&build_semaphore);

   // Only build if build() function is available
   if (buildfile->build_function == "yes")
   {
      // Include buildfile to active builds
      pthread_mutex_lock(&active_builds_mutex);
      BuildManager.active_builds.push_back(buildfile);
      pthread_mutex_unlock(&active_builds_mutex);

      pthread_mutex_lock(&cout_mutex);
      BuildOutputPrint();
      pthread_mutex_unlock(&cout_mutex);

      std::chrono::steady_clock::time_point t1 = std::chrono::steady_clock::now();

      Do("build", buildfile);

      std::chrono::steady_clock::time_point t2 = std::chrono::steady_clock::now();

      auto build_duration = std::chrono::duration_cast<std::chrono::seconds>(t2 - t1);

      // Test for produced package output
      if (FileExist(PackagePath(buildfile)))
         buildfile->have_pkg = true;

      // Remove buildfile from active builds
      pthread_mutex_lock(&active_builds_mutex);
      BuildManager.active_builds.remove(buildfile);
      pthread_mutex_unlock(&active_builds_mutex);

      if (BuildManager.build_error)
      {
         sem_post(&build_semaphore);
         return;
      }

      // Update output
      pthread_mutex_lock(&cout_mutex);
      BuildOutputPrint();
      pthread_mutex_unlock(&cout_mutex);

      // Don't add last build or builds which have no package output
      if ((buildfile != last_build) && buildfile->have_pkg)
      {
         pthread_mutex_lock(&add_mutex);

         pthread_mutex_lock(&active_adds_mutex);
         BuildManager.active_adds.push_back(buildfile);
         pthread_mutex_unlock(&active_adds_mutex);

         Do("add", buildfile);
         pthread_mutex_unlock(&add_mutex);

         pthread_mutex_lock(&cout_mutex);

         // Remove buildfile from active adds
         pthread_mutex_lock(&active_adds_mutex);
         BuildManager.active_adds.remove(buildfile);
         pthread_mutex_unlock(&active_adds_mutex);

         if (BuildManager.build_error)
         {
            sem_post(&build_semaphore);
            return;
         }

         // Output added and advance cursor
         cout << left << setw(OUTPUT_PREFIX_SIZE) << "   Added";
         cout << setw(Dependency.max_name_length + 2) << "'" + buildfile->name + "'";
         if (buildfile->layer != DEFAULT_LAYER_NAME)
            cout << " [" << buildfile->layer << "]";
         cout << " (" << beautify_duration(build_duration) << ")";
         Cursor.clear_rest_of_line();
         cout << endl;
         Cursor.reset_ymaxpos();
         BuildOutputPrint();
         pthread_mutex_unlock(&cout_mutex);
      }

      if (buildfile == last_build)
      {
         // Clear line if it is the last build
         pthread_mutex_lock(&cout_mutex);
         Cursor.clear_rest_of_line();
         pthread_mutex_unlock(&cout_mutex);
      }
   } else
   {
      // in case build function was removed
      // we need remove old build package
      if (FileExist(PackagePath(buildfile)))
	 remove(PackagePath(buildfile).c_str());
   }
   sem_post(&build_semaphore);

};

void CBuildThread::Start(void)
{
   buildthread = new thread(ref(*this));
}

void CBuildThread::Join(void)
{
   buildthread->join();
}

void script_output(void)
{
   int fd, result, count;
   char line_buffer[LINE_MAX];
   fd_set rfds;

   while (1)
   {
      fd = open(SCRIPT_OUTPUT_FIFO.c_str(), O_RDONLY|O_NONBLOCK);

      FD_ZERO(&rfds);
      FD_SET(fd, &rfds);
      result = select(fd+1, &rfds, NULL, NULL, NULL);
      if (result > 0 && FD_ISSET(fd, &rfds))
      {
         count = read(fd, line_buffer, LINE_MAX);
         line_buffer[count]=0;
         pthread_mutex_lock(&cout_mutex);
         cout << line_buffer << flush;
         pthread_mutex_unlock(&cout_mutex);
      }

      close(fd);
   }
}

void CBuildManager::KillBuilds()
{
   list<CBuildFile*>::iterator it;
   pthread_mutex_lock(&active_builds_mutex);

   for (it = BuildManager.active_builds.begin(); it != BuildManager.active_builds.end(); it++)
   {
      if ((*it)->pid == 0)
         continue;

      // Stop build script by killing process group
      if (kill(-(*it)->pid, SIGTERM) != 0)
      {
         // We don't care if the process no longer exists
         if (errno != ESRCH)
            throw runtime_error(strerror(errno));
         // Clean if build was building to avoid corrupt packages
         if ((*it)->build)
            Clean((*it));
      }
   }
   pthread_mutex_unlock(&active_builds_mutex);
}

void CBuildManager::Do(string action, CBuildFile* buildfile)
{
   FILE *fp, *cFile;
   vector<char> log_buffer;
   CStreamDescriptor *stream;
   string arguments;
   string footprint_file;
   string checksum_file;
   string buildfile_checksum_file, source_checksum_file;
   string command;
   stringstream pid;
   char pid_string[PID_MAX_LENGTH];
   string build(buildfile->build ? "yes" : "no");

   if (buildfile->type == "native")
   {
      footprint_file = FOOTPRINT_NATIVE_DIR  "/" +  buildfile->short_name + ".footprint";
      checksum_file = CHECKSUM_NATIVE_DIR  "/" + buildfile->short_name + ".sha256sum";
      buildfile_checksum_file = BUILDFILE_CHECKSUM_NATIVE_DIR "/" + buildfile->short_name + ".sha256sum";
      source_checksum_file = SOURCE_CHECKSUM_NATIVE_DIR "/" + buildfile->short_name + ".sha256sum";
   } 
   else
   {
      footprint_file = FOOTPRINT_CROSS_DIR  "/" + buildfile->short_name + ".footprint";
      checksum_file = CHECKSUM_CROSS_DIR  "/" + buildfile->short_name + ".sha256sum";
      buildfile_checksum_file = BUILDFILE_CHECKSUM_CROSS_DIR "/" + buildfile->short_name + ".sha256sum";
      source_checksum_file = SOURCE_CHECKSUM_CROSS_DIR "/" + buildfile->short_name + ".sha256sum";
   }

   // Set required script arguments

   arguments +=  " --BG_SHORT_NAME '" + buildfile->short_name + "'";
   arguments += " --BG_BUILD_FILE '" + buildfile->filename + "'";
   arguments += " --BG_ACTION '" + action + "'";
   arguments += " --BG_BUILD_FILES_CONFIG '" BUILD_FILES_CONFIG "'";
   arguments += " --BG_BUILD_TYPE '" + buildfile->type + "'";
   arguments += " --BG_WORK_DIR '" WORK_DIR "'";
   arguments += " --BG_PACKAGE_DIR '" PACKAGE_DIR "'";
   arguments += " --BG_OUTPUT_DIR '" OUTPUT_DIR "'";
   arguments += " --BG_SOURCE_DIR '" + Config.bg_config[CONFIG_KEY_SOURCE_DIR] + "'";
   arguments += " --BG_SYSROOT_DIR '" SYSROOT_DIR "'";
   arguments += " --BG_BUILD '" + Config.bf_config[CONFIG_KEY_BUILD] + "'";
   arguments += " --BG_HOST '" + Config.bf_config[CONFIG_KEY_HOST] + "'";
   arguments += " --BG_VERBOSE 'no'";
   arguments += " --BG_BUILD_FOOTPRINT '" + footprint_file + "'";
   arguments += " --BG_BUILD_SHA256SUM '" + checksum_file + "'";
   arguments += " --BG_BUILDFILE_SHA256SUM '" + buildfile_checksum_file + "'";
   arguments += " --BG_SOURCE_SHA256SUM '" + source_checksum_file + "'";
   arguments += " --BG_MAX_NAME_LEN '" + to_string(Dependency.max_name_length) + "'";
   arguments += " --BG_MAX_LAYER_LEN '" + to_string(Dependency.max_layer_length) + "'";
   arguments += " --BG_SCRIPT_OUTPUT_FIFO '" + SCRIPT_OUTPUT_FIFO + "'";
   arguments += " --BG_TEMP_DIR '" + Config.tmp_dir + "'";

   if (buildfile->layer != DEFAULT_LAYER_NAME)
      arguments +=" --BG_LAYER '" + buildfile->layer + "'";

   // Apply build settings to all builds if '--all' is used
   if (Config.all)
   {
      arguments += " --BG_BUILD_BUILD '" + build + "'";
      arguments += " --BG_UPDATE_CHECKSUM '" + Config.update_checksum + "'";
      arguments += " --BG_UPDATE_FOOTPRINT '" + Config.update_footprint + "'";
      arguments += " --BG_KEEP_WORK '" + Config.keep_work + "'";
      if (Config.no_strip == "yes")
         arguments += " --BG_NO_STRIP '" + Config.no_strip + "'";
      else
         arguments += " --BG_NO_STRIP '" + buildfile->options.nostrip + "'";
   } else
   {
      // Apply settings to main build
      if (Config.name == buildfile->name)
      {
         arguments += " --BG_BUILD_BUILD '" + build + "'";
         arguments += " --BG_UPDATE_CHECKSUM '" + Config.update_checksum + "'";
         arguments += " --BG_UPDATE_FOOTPRINT '" + Config.update_footprint + "'";
         arguments += " --BG_KEEP_WORK '" + Config.keep_work + "'";
         if (Config.no_strip == "yes")
            arguments += " --BG_NO_STRIP '" + Config.no_strip + "'";
         else
            arguments += " --BG_NO_STRIP '" + buildfile->options.nostrip + "'";
      } else
      {
         // Apply default settings to the build dependencies
         arguments += " --BG_BUILD_BUILD '" + build + "'";
         arguments += " --BG_UPDATE_CHECKSUM 'no'";
         arguments += " --BG_UPDATE_FOOTPRINT 'no'";
         arguments += " --BG_KEEP_WORK 'no'";
         arguments += " --BG_NO_STRIP '" + buildfile->options.nostrip + "'";
      }
   }

   command = SCRIPT " " + arguments;

   /* Make sure we are using bash */
   command = "bash --norc --noprofile -O extglob -c 'setsid " + command + " 2>&1' 2>&1";

   /* Create fifo for build script PID */
   unlink(buildfile->control_fifo);
   if (mkfifo(buildfile->control_fifo, S_IRWXU) != 0)
      throw runtime_error(strerror(errno));

   pthread_mutex_lock(&active_builds_mutex);

   if (BuildManager.build_error)
   {
      pthread_mutex_unlock(&active_builds_mutex);
      return;
   }

   /* Execute command */
   fp = popen(command.c_str(), "r");
   if (fp == NULL)
   {
      cout << "\npopen() failed\n";
      exit(EXIT_FAILURE);
   }

   /* Get the build script PID */
   cFile = fopen(buildfile->control_fifo, "r");
   if (!cFile)
      throw runtime_error(strerror(errno));

   if (fgets(pid_string, PID_MAX_LENGTH, cFile) != NULL)
   {
      buildfile->pid = atoi(pid_string);
   }
   else
      throw runtime_error(strerror(errno));

   pthread_mutex_unlock(&active_builds_mutex);

   // Remove the PID fifo
   unlink(buildfile->control_fifo);

   if (!BuildManager.build_error)
   {
      stream = Log.add_stream(fp, buildfile);

      // Wait for the build to be done
      unique_lock<mutex> lock(stream->done_mutex);
      while (!stream->done_flag)
         stream->done_cond.wait(lock);
   }

   if (pclose(fp) != 0)
   {
      list<CStreamDescriptor*>::iterator log_it;

      if (!BuildManager.build_error)
      {
         // Clean the log stream queue for other builds
         Log.log_streams_mutex.lock();

         Log.log_streams.remove_if([stream] (CStreamDescriptor* val) -> bool { return val != stream;});

         Log.log_streams_mutex.unlock();

         BuildManager.build_error = true;
      }

      // Stop running builds
      KillBuilds();
   }
}

string CBuildManager::PackagePath(CBuildFile *buildfile)
{
   string package;

   package = PACKAGE_DIR "/" +
             buildfile->name + "#" +
             buildfile->version + "-" +
             buildfile->release + PACKAGE_EXTENSION;

   return package;
}

bool CBuildManager::PackageExists(CBuildFile *buildfile)
{
   string package;

   package = PackagePath(buildfile);

   if (!FileExist(package))
      return (buildfile->build_function == "no");

   return true;
}

bool CBuildManager::PackageUpToDate(CBuildFile *buildfile)
{
   string package;

   package = PackagePath(buildfile);

   if (!FileExist(package))
      return (buildfile->build_function == "no");

   if (difftime(Age(package), Age(buildfile->filename)) > 0)
      return true;

   return false;
}

bool CBuildManager::SourceUpToDate(CBuildFile *buildfile)
{
   istringstream iss(buildfile->source);
   string item;
   string source;
   string package;
   size_t pos;

   package = PackagePath(buildfile);

   if (!FileExist(package))
      return (buildfile->build_function == "no");

   while ( getline(iss, item, ' ') )
   {
      if (Source.Remote(item))
      {
         // If source is remote, look in the source directory
         pos = item.find_last_of('/');
         source = Config.bg_config[CONFIG_KEY_SOURCE_DIR] + "/" +
                  item.substr(pos + 1);
      } else {
         source = buildfile->GetLocation() + item;
      }

      if (difftime(Age(package), Age(source)) < 0)
         return false;
   }

   return true;
}

bool CBuildManager::SourceChecksumMismatch(CBuildFile *buildfile)
{
   // Verify sources checksum for buildfiles with build() function only else
   // assume no checksum mismatch
   if (!buildfile->source.empty() )
   {
      //printf("***  buildfile '%s' has source '%s'**\n\n", buildfile->short_name.c_str(), buildfile->source.c_str());
      return buildfile->SourceChecksumMismatch();
   }
   else
   {
      //printf("***  buildfile '%s' has no source **\n\n", buildfile->short_name.c_str() );
      return false;
   }
}

bool CBuildManager::BuildfileChecksumMismatch(CBuildFile *buildfile)
{
   // Verify buildfile checksum for buildfiles with build() function only else
   // assume no checksum mismatch
   if (buildfile->build_function == "yes")
      return buildfile->BuildfileChecksumMismatch();
   else
      return false;
}

bool CBuildManager::DepBuildNeeded(CBuildFile *buildfile, time_t age)
{
   list<CBuildFile*>::iterator it;

   string package(PackagePath(buildfile));

   if (FileExist(package))
      age = Age(package);

   for (it=buildfile->dependency.begin(); it!=buildfile->dependency.end(); ++it)
   {
      if ((*it)->build)
      {
         printf("*** Building '%s' because dependency '%s' is being built ***\n", buildfile->short_name.c_str(), (*it)->short_name.c_str());
         return true;
      }

      //package = PackagePath(*it);
      //if (FileExist(package) && (difftime(Age(package), age) > 0))
      //   return true;

      if (DepBuildNeeded(*it, age))
         return true;
   }

   return false;
}

void CBuildManager::Build(list<CBuildFile*> *buildfiles)
{
   list<CBuildFile*>::iterator it;
   list<CBuildFile*>::reverse_iterator rit;

   // Set build error flag
   BuildManager.build_error = false;

   // Create fifo for build output communication
   unlink(SCRIPT_OUTPUT_FIFO.c_str());
   if (mkfifo(SCRIPT_OUTPUT_FIFO.c_str(), S_IRWXU) != 0)
      throw std::runtime_error(strerror(errno));

   // Start build script output communication thread
   thread script_output_thread(script_output);
   script_output_thread.detach();

   // Set build action of all builds based on package vs. buildfile age,
   // package vs source age, and mismatching buildfile checksum
   for (it=buildfiles->begin(); it!=buildfiles->end(); it++)
   {
      // Does the package exist!!
      if ( !PackageExists((*it)) )
      {
         printf("*** Building '%s' because package doesn't exist ***\n", (*it)->short_name.c_str());
         (*it)->build = true;  
      }

      if ( BuildfileChecksumMismatch( (*it)) )
      {
         printf("*** Building '%s' because buildfile checksum doesn't match ***\n", (*it)->short_name.c_str());
         (*it)->build = true;  
      }
      
      if ( SourceChecksumMismatch( (*it)) )
      {
         printf("*** Building '%s' because source checksum doesn't match ***\n", (*it)->short_name.c_str());
         (*it)->build = true;
      }

      //if (!PackageUpToDate((*it)) || !SourceUpToDate((*it)) || BuildfileChecksumMismatch((*it)))
      //   (*it)->build = true;
   }

   // Set build action of all builds (based on dependencies build status)
   for (it=buildfiles->begin(); it!=buildfiles->end(); it++)
   {
      // Skip if build action already set
      if ((*it)->build)
         continue;

      // If one or more dependencies needs to be build
      if (DepBuildNeeded(*it, numeric_limits<time_t>::max()))
      {
         // Then build is needed
         (*it)->build = true;
      } 
      else
      {
         // Else no build is needed
         (*it)->build = false;
      }
   }

   // Only build if main build requires a build
   if ((buildfiles->back()->build) ||
       (Config.update_footprint=="yes") ||
       (Config.update_checksum=="yes"))
   {
      cout << endl;

      vector<CBuildThread *> builder;

      // Initialize build semaphore
      if (sem_init(&build_semaphore, 0,
                   stoi(Config.bg_config[CONFIG_KEY_PARALLEL_BUILDS])) == -1)
      {
         cerr << "Error: Build semaphore init failed" << endl;
         exit(EXIT_FAILURE);
      }

      // Start with buildfiles of depth 0
      int current_depth = buildfiles->front()->depth;
      last_build = buildfiles->back();

      // Process build order
      it=buildfiles->begin();
      while (it != buildfiles->end())
      {
         int thread_count=0;
         list<CBuildFile*> locked_buildfiles;
         list<CBuildFile*>::iterator itr;

         // Start building threads of same depth in parallel
         while ( (it != buildfiles->end()) && ((*it)->depth == current_depth)
                 && !BuildManager.build_error)
         {
            // Only build buildfiles in parallel which are not marked with the
            // "buildlock" option
            if ((*it)->options.buildlock == false)
            {
               CBuildThread *bt = new CBuildThread(*it);
               builder.push_back(bt);
               builder[thread_count]->Start();
               thread_count++;
            }
            else
            {
                // Add for later sequential build deployment
                locked_buildfiles.push_back(*it);
            }
            it++;
         }

         // Wait for thread_count build threads to complete
         for (int i=0; i<thread_count; i++)
         {
            if (BuildManager.build_error)
               break;
            builder[i]->Join();
            delete builder[i];
            builder.pop_back();
         }

         // Build "buildlock" marked builds sequentially
         for (itr = locked_buildfiles.begin(); itr != locked_buildfiles.end(); itr++)
         {
            CBuildThread *bt = new CBuildThread(*itr);
            (bt)->Start();
            (bt)->Join();
            if (BuildManager.build_error)
               break;
         }

         locked_buildfiles.clear();

         if (BuildManager.build_error)
            break;

         // Proceed to next depth level
         current_depth++;
      }
      sem_destroy(&build_semaphore);
   }
   // Building done - clean up build script fifo
   unlink(SCRIPT_OUTPUT_FIFO.c_str());
}

void CBuildManager::Clean(CBuildFile *buildfile)
{
   string command;

   if (!BuildManager.build_error)
      cout << "\nCleaning build '" << buildfile->name << "'.. ";

   command  = "rm -f ";
   command += string(PACKAGE_DIR) + "/" +
              buildfile->name + "#" +
              buildfile->version + "-" +
              buildfile->release +
              PACKAGE_EXTENSION;

   if (system(command.c_str()) < 0)
      perror("error\n");
}

void CBuildManager::CleanAll(void)
{
   CleanPackages();
   CleanWork();
}

void CBuildManager::CleanDependencies(CBuildFile *buildfile)
{
   list<CBuildFile*> resolved, unresolved;
   list<CBuildFile*>::iterator it;

   Dependency.ResolveDependency(buildfile, &resolved, &unresolved);

   for (it = resolved.begin(); it != resolved.end(); it++)
      Clean((*it));
}

void CBuildManager::CleanFootprint(CBuildFile *buildfile)
{
   string command;

   cout << "\nCleaning footprint for build '" << buildfile->name << "'..";

   command = "rm -f ";
   if (buildfile->type == "native")
      command += FOOTPRINT_NATIVE_DIR "/";
   else
      command += FOOTPRINT_CROSS_DIR "/";
   command += buildfile->short_name + ".footprint";

   if (system(command.c_str()) < 0)
      perror("error\n");
}

void CBuildManager::CleanDependenciesFootprint(CBuildFile *buildfile)
{
   list<CBuildFile*> resolved, unresolved;
   list<CBuildFile*>::iterator it;

   Dependency.ResolveDependency(buildfile, &resolved, &unresolved);

   for (it = resolved.begin(); it != resolved.end(); it++)
      CleanFootprint((*it));
}

void CBuildManager::CleanAllFootprint(void)
{
   string command;

   command = "rm -f ";
   command += FOOTPRINT_NATIVE_DIR "/*";

   if (system(command.c_str()) < 0)
      perror("error\n");

   command = "rm -f ";
   command += FOOTPRINT_CROSS_DIR "/*";

   if (system(command.c_str()) < 0)
      perror("error\n");
}

void CBuildManager::CleanChecksum(CBuildFile *buildfile)
{
   string command;

   cout << "\nCleaning checksum for build '" << buildfile->name << "'..";

   command = "rm -f ";
   if (buildfile->type == "native")
      command += CHECKSUM_NATIVE_DIR "/";
   else
      command += CHECKSUM_CROSS_DIR "/";
   command += buildfile->short_name + ".sha256sum";

   if (system(command.c_str()) < 0)
      perror("error\n");
}

void CBuildManager::CleanDependenciesChecksum(CBuildFile *buildfile)
{
   list<CBuildFile*> resolved, unresolved;
   list<CBuildFile*>::iterator it;

   Dependency.ResolveDependency(buildfile, &resolved, &unresolved);

   for (it = resolved.begin(); it != resolved.end(); it++)
      CleanChecksum((*it));
}

void CBuildManager::CleanAllChecksum(void)
{
   string command;

   command = "rm -f ";
   command += CHECKSUM_NATIVE_DIR "/*";

   if (system(command.c_str()) < 0)
      perror("error\n");

   command = "rm -f ";
   command += CHECKSUM_CROSS_DIR "/*";

   if (system(command.c_str()) < 0)
      perror("error\n");
}

void CBuildManager::CleanPackages(void)
{
   if (system("rm -rf " PACKAGE_DIR) < 0)
	   perror("error\n");
}

void CBuildManager::CleanWork(void)
{
   if (system("rm -rf " WORK_DIR) < 0)
	   perror("error\n");
}

void CBuildManager::BuildOutputTick(CBuildFile *buildfile)
{
   if (++buildfile->tick >= 4)
      buildfile->tick = 0;

   pthread_mutex_lock(&cout_mutex);
   BuildOutputPrint();
   pthread_mutex_unlock(&cout_mutex);
}

void CBuildManager::BuildOutputPrint()
{
   string indicator;
   list<CBuildFile*>::const_iterator it;
   int lines = 0;

   pthread_mutex_lock(&active_adds_mutex);

   Cursor.reset_ymaxpos();

   for (it = BuildManager.active_adds.begin(); it != BuildManager.active_adds.end(); it++)
   {
      cout << left << setw(OUTPUT_PREFIX_SIZE) << "   Adding";
      cout << setw(Dependency.max_name_length + 2) << "'" + (*it)->name + "'";
      if ((*it)->layer != DEFAULT_LAYER_NAME)
         cout << " [" << (*it)->layer << "]";
      Cursor.clear_rest_of_line();
      cout << endl;
      lines++;
      Cursor.ypos_add(1);
   }

   pthread_mutex_unlock(&active_adds_mutex);
   pthread_mutex_lock(&active_builds_mutex);

   for (it = BuildManager.active_builds.begin(); it != BuildManager.active_builds.end(); it++)
   {
      // Do not show output if buildfile is not a build
      if (!(*it)->build)
         continue;

      switch ((*it)->tick)
      {
         case 0:
            indicator = "-";
            break;
         case 1:
            indicator = "\\";
            break;
         case 2:
            indicator = "|";
            break;
         case 3:
            indicator = "/";
      }

      cout << " " << setw(1) << indicator << left << setw(OUTPUT_PREFIX_SIZE - 2) << " Building";
      cout << setw(Dependency.max_name_length + 2) << "'" + (*it)->name + "'";
      if ((*it)->layer != DEFAULT_LAYER_NAME)
         cout << " [" << (*it)->layer << "]";
      Cursor.clear_rest_of_line();
      cout << endl;
      lines++;
      Cursor.ypos_add(1);
   }

   pthread_mutex_unlock(&active_builds_mutex);

   Cursor.clear_below();
   Cursor.line_up(lines);
   cout << "\r" << flush;
}
