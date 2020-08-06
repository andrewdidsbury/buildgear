/*
 * This file is part of Build Gear.
 *
 * Copyright (C) 2011-2013  Martin Lund
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

#ifndef BUILDMANAGER_H
#define BUILDMANAGER_H

#include "buildgear/config.h"
#include "buildgear/filesystem.h"
#include "buildgear/options.h"
#include <mutex>

using namespace std;

class CBuildManager : public CFileSystem, COptions
{
   public:
      void Build(list<CBuildFile*> *);
      void Do(string, CBuildFile*);
      void Clean(CBuildFile *);
      void CleanAll(void);
      void CleanDependencies(CBuildFile *);
      void CleanFootprint(CBuildFile *);
      void CleanAllFootprint(void);
      void CleanDependenciesFootprint(CBuildFile *);
      void CleanChecksum(CBuildFile *);
      void CleanDependenciesChecksum(CBuildFile *);
      void CleanAllChecksum(void);
      void CleanPackages(void);
      void CleanWork(void);
      string PackagePath(CBuildFile *);
      bool PackageExists(CBuildFile *);
      bool PackageUpToDate(CBuildFile *);
      bool SourceUpToDate(CBuildFile *);
      bool BuildfileChecksumMismatch(CBuildFile *);
      bool SourceChecksumMismatch(CBuildFile *);
      bool DepBuildNeeded(CBuildFile *buildfile);
      void BuildOutputTick(CBuildFile *buildfile);
      void BuildOutputPrint(void);
      void KillBuilds(void);
      bool IsBuildRequired( CBuildFile * );
      bool DownloadPackage( CBuildFile * );
      
      void PushToPackageManager( list<CBuildFile*> *buildfiles );
      bool SearchPackageManger( string name );

      list<CBuildFile*> active_builds;
      list<CBuildFile*> active_adds;
      bool build_error;
      
      list<CBuildFile*> pkg_download_queue;
      mutex pkg_download_mutex;

      list<CBuildFile*> pkg_upload_queue;
      mutex pkg_upload_mutex;
   private:

      bool UploadFile( string url, string auth, string file);
      bool DownloadFile( string url, string filename );

      void GetPackageManagerUrls( CBuildFile * b, string & src_checksum_url, string & build_checksum_url, string & package_url );
      void GetPackageManagerFilePaths( CBuildFile * b, string & src_checksum_path, string & build_checksum_path, string & package_path );

      void DownloadPackagesThread();
      void UploadPackagesThread();
};

#define PID_MAX_LENGTH 10

extern CBuildManager BuildManager;
#endif
