#ifndef BUILDFILES_H
#define BUILDFILES_H

#include <list>
#include "buildgear/filesystem.h"

using namespace std;

class CBuildFile
{
   public:
      CBuildFile(string filename);
      string filename;
      string name;
      string version;
      string release;
      string source;
      string depends;
      string host_depends;
      string target_depends;
      string type;
      list<CBuildFile*> host_dependency;
      list<CBuildFile*> target_dependency;
      list<CBuildFile*> host_resolved;
      list<CBuildFile*> host_unresolved;
   private:
};

class CBuildFiles
{
   public:
      list<CBuildFile*> host_buildfiles;
      list<CBuildFile*> target_buildfiles;
      void ParseAndVerify(list<CBuildFile*> *buildfiles, bool type);
      void ShowMeta(list<CBuildFile*> *buildfiles);
      void LoadDependency(list<CBuildFile*> *buildfiles);
   private:
};

#endif
