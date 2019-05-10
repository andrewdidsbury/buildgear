/*
 * This file is part of Build Gear.
 *
 * Copyright (c) 2012-2013  Jesper Larsen
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
#include <stdexcept>
#include <curses.h>
#include <errno.h>
#include <term.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include "buildgear/cursor.h"

#define DISABLE_CURSOR

pthread_mutex_t cout_mutex = PTHREAD_MUTEX_INITIALIZER;

void cursor_restore()
{
   Cursor.restore();
   Cursor.enable_wrap();

   // Make sure terminal echo is reenabled
   Cursor.enable_echo();
}

CCursor::CCursor()
{
   char *temp;
   int err;

   // Setup terminfo database based on the TERM environment variable
   if (setupterm(NULL, 1, &err) == ERR)
   {
      cout << "Error: Terminfo setupterm failed (" << err << ")";
      exit(EXIT_FAILURE);
   }

   // Get number of lines in terminal
   no_lines = tgetnum((char *)"li");

   // Get number of cols in terminal
   no_cols = tgetnum((char *)"co");

#ifndef DISABLE_CURSOR

   // Request padding character
   temp = tgetstr((char *)"pc", NULL);
   PC = temp ? *temp : 0;

   // Get string for moving cursor #1 lines up
   UP =  tgetstr((char *)"UP", NULL);

   // Get string for moving cursor #1 lines down
   DO =  tgetstr((char *)"DO", NULL);

   // Get string to clear from cursor to end of line
   ce =  tgetstr((char *)"ce", NULL);

   // Get string to make cursor invisible
   vi =  tgetstr((char *)"vi", NULL);

   // Get string to make cursor visible
   ve =  tgetstr((char *)"ve", NULL);

   // Get string to move cursor to lower left corner
   ll =  tgetstr((char *)"ll", NULL);

   // Get string to clear lines below cursor
   cd =  tgetstr((char *)"cd", NULL);

   // Get string to disable auto margin
   RA = tgetstr((char *)"RA", NULL);

   // Get string to enable auto margin
   SA = tgetstr((char *)"SA", NULL);

   // Relative cursor placement
   ypos = 0;
   #endif
}

void CCursor::line_down(int num)
{
#ifndef DISABLE_CURSOR
   char *down;

   if (num == 0)
      return;

   down = tparm(DO, num);

   putp(down);
   fflush(stdout);

   ypos += num;

   if (ypos > max_ypos)
      max_ypos = ypos;
#endif
}

void CCursor::line_up(int num)
{
#ifndef DISABLE_CURSOR
   char *up;

   if (num == 0)
      return;

   up = tparm(UP, num);

   putp(up);
   fflush(stdout);

   ypos -= num;
#endif
}

void CCursor::clear_rest_of_line()
{
#ifndef DISABLE_CURSOR
   putp(ce);
   fflush(stdout);
#endif
}

void CCursor::clear_below()
{
   putp(cd);
   fflush(stdout);
}

void CCursor::show()
{
#ifndef DISABLE_CURSOR
   putp(ve);
   fflush(stdout);
#endif
}

void CCursor::hide()
{
#ifndef DISABLE_CURSOR
   putp(vi);
   fflush(stdout);
#endif
}

void CCursor::restore()
{
#ifndef DISABLE_CURSOR
   line_down(max_ypos - ypos);
   show();
   fflush(stdout);
#endif
}

void CCursor::ypos_add(int num)
{
#ifndef DISABLE_CURSOR
   ypos += num;

   if (ypos > max_ypos)
      max_ypos = ypos;
#endif
}

int CCursor::get_ypos()
{
   return ypos;
}

void CCursor::update_num_cols()
{
#ifndef DISABLE_CURSOR
   struct winsize w;

   ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);

   no_cols = w.ws_col;
#endif
}

void CCursor::enable_wrap()
{
#ifndef DISABLE_CURSOR
   putp(SA);
   fflush(stdout);
#endif
}

void CCursor::disable_wrap()
{
#ifndef DISABLE_CURSOR
   putp(RA);
   fflush(stdout);
#endif
}

void CCursor::reset_ymaxpos()
{
   max_ypos = 0;
}

void CCursor::enable_echo()
{
#ifndef DISABLE_CURSOR
   if (isatty(fileno(stdin)))
      if (system("stty echo")) ;
#endif
}

void CCursor::disable_echo()
{
#ifndef DISABLE_CURSOR
   if (isatty(fileno(stdin)))
      if (system("stty -echo")) ;
#endif
}
