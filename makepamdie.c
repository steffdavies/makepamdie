/*  makepamdie - replacement for Sun's pamverifier, which I couldn't get working on
    Debian. Pamverifier takes a command line arg "authuser" followed by a username
    and pass on successive lines of stdin. We do just enough to imitate the case of
    root logons to Sun Common Array Manager on Debian, so we fail for non-root users
    and require MD5 passwords marked $1$ (the FreeBSD-derived scheme by Poul-Henning
    Kamp). NB that this won't work on eg. recent Ubuntus.

Compile: gcc -lcrypt -o makepamdie makepamdie.c

The binary must be suid root as it needs to read /etc/shadow when run by the
Java ghastliness as "nobody".
 */

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

int main (int argc, char **argv)
{
  const char *shadow = "/etc/shadow";
  char shadow_line_buf[LINE_MAX+1];
  char username[LINE_MAX+1];
  char pass[LINE_MAX+1];
  char salt[13]; // 3-char "$1$" MD5 flag, 8-char salt, $ + zero byte
  char shadow_hash[23]; // 22-char md5 hash + zero byte
  char extracted[36]; // 22-char md5 hash + zero byte
  int i;
  FILE *ret;
  char *crypted;
  size_t matchcount;

  ret=fopen(shadow, "re");

  if (!ret)
  {
    printf("Failed to open shadow file\n");
    cark();
  }

  fgets(username,LINE_MAX,stdin);
  if (strcmp("root\n",username)!=0)
  {
    cark();
  }
  fgets(pass,LINE_MAX,stdin);
  pass[strlen(pass)-1]=0;

  while ((fgets(shadow_line_buf, LINE_MAX+1, ret) != NULL))
  {
    if (strncmp("root:$1$",shadow_line_buf,8)==0)
    {
      for (i=0; i<15; i++)
      {
        salt[i]=shadow_line_buf[i+5];
      }
      salt[12]=0;
      for (i=0; i<22; i++)
      {
        shadow_hash[i]=shadow_line_buf[i+17];
      }
      shadow_hash[22]=0;
      strcpy(extracted, salt);
      strcat(extracted, shadow_hash);
      crypted=crypt(pass,salt);
      if (!strcmp(extracted, crypted))
      {
        printf("0\n");
        exit(0);
      }
      else
      {
        cark();
      }
    }

  }
  cark();
}

cark ()
{
  printf("-1\n");
  exit(1);
}