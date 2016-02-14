#include "hdb.h"
#include <stdlib.h>
#include <hiredis/hiredis.h>
#include <zlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>




hdb_connection* hdb_connect(const char* server) {
  // Connect to the Redis server.
  // See https://github.com/redis/hiredis/blob/master/examples/example.c
  //
  // Cast the redisContext to an hdb_connection.
  // See the definition of hdb_connection in hdb.h -- notice that it's
  // just a typedef of void* (i.e. an alias of void*).
  //
  // Why are we doing this?  To hide our implementation details from
  // any users of the library.  We want to be able to change our
  // implementation at any time without affecting external code.
  // We don't want external users of the code to know we're using
  // Redis, so that, if we decided to switch to another data store
  // in the future, we could make the change internally, and no
  // external code would break.
  //
  // To avoid a compiler warning when casting the redisContext to
  // an hdb_connection, you may find the following line helpful
  // (don't be scared):
  // return *(hdb_connection**)&context;

  //
  redisContext *c = redisConnect(server, 6379);
  if (c != NULL && c->err) {
    printf("Error: %s\n", c->errstr);
    // handle error
  }
  return *(hdb_connection**)&c;
}

void hdb_disconnect(hdb_connection* con)
{
  // "Disconnect" from the Redis server (i.e. free the Redis context)
  redisContext *c = (redisContext*)con;
  redisFree(c);

}

void hdb_store_file(hdb_connection* con, hdb_record* record) {
  // Store the specified record in the Redis server.  There are many ways to
  // do this with Redis.  Whichever way you choose, the checksum should be
  // associated with the file, and the file should be associated with the user.
  //
  // Hint: look up the HSET command.
  //
  // typedef struct hdb_record {
  //   char* username;
  //   char* filename;
  //   char* checksum;
  //   struct hdb_record* next;
  // } hdb_record;
  char *username = (*record).username;
  char *filename = (*record).filename;
  char *checksum = (*record).checksum;
  //redisReply *reply;
  redisContext *c = (redisContext*)con;
  redisReply *reply = redisCommand(c,"HSET %s %s %s", username, filename, checksum);
  //redisReply *reply = redisCommand(c,"HMSET %s filename %s checksum %s", username, filename, checksum);
  //printf("SET: %s\n", reply->str);
  freeReplyObject(reply);
  //redisReply *reply1 = redisCommand(c, "HMSET %s checksum %s", filename, checksum);
  //printf("SET: %s\n", reply1->str);
  //freeReplyObject(reply1);
}

int hdb_remove_file(hdb_connection* con, const char* username, const char* filename) {
  // Remove the specified file record from the Redis server.
  redisContext *c = (redisContext*)con;
  redisReply *reply = redisCommand(c, "HDEL %s filename %s", username, filename);
  int response = reply->integer;
  freeReplyObject(reply);
  return response; // Remove me
}

char* hdb_file_checksum(hdb_connection* con, const char* username, const char* filename) {
  // If the specified file exists in the Redis server, return its checksum.
  // Otherwise, return NULL.
  redisContext *c = (redisContext*)con;
  redisReply *reply = redisCommand(c, "HGET %s %s", username, filename);
  //DOUBLE CHECK IS THE CHECKSUM GETS STORED AS A INT OR string
  char *string = (reply->str);
  if (string != NULL){
    return string;
  }
  return NULL;
}

int hdb_file_count(hdb_connection* con, const char* username) {
  // Return a count of the user's files stored in the Redis server.
  redisContext *c = (redisContext*)con;
  redisReply* reply = redisCommand(c, "HLEN %s", username);
  int count = reply->integer;
  freeReplyObject(reply);
  //int returnValue = (int)( sizeof(array) / sizeof(array[0]));
  return count; // Remove me
}

bool hdb_user_exists(hdb_connection* con, const char* username) {
  // Return a Boolean value indicating whether or not the user exists in
  // the Redis server (i.e. whether or not he/she has files stored).
  redisContext *c = (redisContext*)con;
  redisReply *reply = redisCommand(c, "HLEN %s", username);
  int exists = (reply->integer);
  if (exists >= 1) {
    return true;
  }else
  return false; // Remove me
}

bool hdb_file_exists(hdb_connection* con, const char* username, const char* filename) {
  // Return a Boolean value indicating whether or not the file exists in
  // the Redis server.
  redisContext *c = (redisContext *)con;
  redisReply *reply = redisCommand(c, "HEXISTS %s %s", username, filename);
  int exists = reply->integer;
  freeReplyObject(reply);
  if(exists == 1){
    return true;
  }else
  return false; // Remove me
}

hdb_record* hdb_user_files(hdb_connection* con, const char* username) {
  // Return a linked list of all the user's file records from the Redis
  // server.  See the hdb_record struct in hdb.h  -- notice that it
  // already has a pointer 'next', allowing you to set up a linked list
  // quite easily.
  //
  // If the user has no files stored in the server, return NULL.
  redisContext *c = (redisContext *)con;
  redisReply  *reply = redisCommand(c, "HGETALL %s", username);
  if (reply->integer == 0){
    return NULL;
  }
  struct hdb_record* head = (struct hdb_record *)malloc(sizeof(struct hdb_record));
  struct hdb_record* tail = (struct hdb_record *)malloc(sizeof(struct hdb_record));
  const char *name = username;
  if (reply->type == REDIS_REPLY_ARRAY && reply->element[0] != NULL) {
    for (int j = 0; j < reply->elements; j++) {
      printf("%u) %s\n", j, reply->element[j]->str);
      head->next = NULL;
      head->username = (char *)name;
      head->filename = reply->element[j]->str;
      head->checksum = reply->element[j+1]->str;
      head->next = tail;
      j++;
    }
    return head; // Remove me
  }
  return NULL; // Remove me
}

void hdb_free_result(hdb_record* record) {
  // Free up the memory in a linked list allocated by hdb_user_files().
  free(record);
}

int hdb_delete_user(hdb_connection* con, const char* username) {
  // Delete the user and all of his/her file records from the Redis server.
  redisContext *c = (redisContext *)con;
  redisReply *reply = redisCommand(c, "DEL %s", username);
  int returnValue = reply->integer;
  freeReplyObject(reply);
  return returnValue; // Remove me
}

void gen_random(char *s, const int len) {
  static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s[len] = 0;
}

char* hdb_authenticate(hdb_connection* con, const char* username, const char* password)
{
  // Return a Boolean value indicating whether or not the user exists in
  // the Redis server (i.e. whether or not he/she has files stored).
  redisContext *c = (redisContext*)con;
  redisReply *passwordReply = redisCommand(c, "HGET db %s %s", username, password);
  char *passwordResponse = (passwordReply->str);
  if (passwordResponse != NULL){
    char *token = malloc(sizeof(*token));
    gen_random(token, 16);
    redisReply *authReply = redisCommand(c, "HSET db authToken %s username %s", token, username);
    freeReplyObject(authReply);
    freeReplyObject(passwordReply);
  } else {
    redisReply *reply = redisCommand(c, "HGET db username %s password %s", username, password);
    freeReplyObject(reply);
  }
  return "token";

}

char* hdb_verify_token(hdb_connection* con, const char* token)
{
  redisContext *c = (redisContext*)con;
  redisReply *reply = redisCommand(c, "HGET db authToken %S", token);
  char *authToken = reply->str;
  freeReplyObject(reply);
  if(authToken != NULL){
    return authToken;
  }
  return "error";
}
