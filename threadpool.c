//
// Created by Amit cohen, id 315147330 on 08/12/2021.
//
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "threadpool.h"
void add_task_to_Q(threadpool* pool,work_t * task);
threadpool* create_threadpool(int num_threads_in_pool){
    if(num_threads_in_pool>MAXT_IN_POOL||num_threads_in_pool<0)
        return NULL;
    threadpool * pool=(threadpool*) malloc(sizeof (threadpool));
    pool->num_threads=num_threads_in_pool;
    pool->qsize=0;
    pool->threads=(pthread_t*) malloc(sizeof (pthread_t)*num_threads_in_pool);
    pool->qhead=NULL;
    pool->qtail=NULL;
    pool->shutdown=0;
    pool->dont_accept=0;
    pthread_mutex_init(&pool->qlock, NULL);
    pthread_cond_init(&pool->q_empty, NULL);
    pthread_cond_init(&pool->q_not_empty, NULL);
    for (int i = 0; i < num_threads_in_pool; i++)
        pthread_create(pool->threads + i, NULL, do_work, (void*)pool);
    return pool;
}
void* do_work(void* p){
    threadpool *pool=(threadpool*)p;
    while (1) {
        pthread_mutex_lock(&pool->qlock);
        if(pool->shutdown) {
            pthread_mutex_unlock(&pool->qlock);
            return NULL;
        }
        if (!pool->qsize) {
            if (pool->shutdown) {
                pthread_mutex_unlock(&pool->qlock);
                return NULL;
            }
            else {
                pthread_cond_wait(&pool->q_not_empty, &pool->qlock);
                if(pool->shutdown) {
                    pthread_mutex_unlock(&pool->qlock);
                    return NULL;
                }
                pthread_mutex_unlock(&pool->qlock);
            }
        }
        else if(pool->qsize>0){
            work_t * w=pool->qhead;
            if(w==NULL) {
                pthread_mutex_unlock(&pool->qlock);
                continue;
            }
            pool->qhead=pool->qhead->next;
            pool->qsize--;
            if(!pool->qsize&&pool->dont_accept)
                pthread_cond_signal(&pool->q_empty);
            pthread_mutex_unlock(&pool->qlock);
            w->routine(w->arg);
            free(w);
            w=NULL;
        }
    }
}
void destroy_threadpool(threadpool* destroyme){
    pthread_mutex_lock(&destroyme->qlock);
    destroyme->dont_accept=1;

    if(destroyme->qsize>0)
      pthread_cond_wait(&destroyme->q_empty,&destroyme->qlock);
    destroyme->shutdown=1;
    pthread_mutex_unlock(&destroyme->qlock);
    pthread_cond_broadcast(&destroyme->q_not_empty);
    for (int i = 0; i <destroyme->num_threads; i++)
        pthread_join(destroyme->threads[i], NULL);
    work_t * a=destroyme->qhead,*b=NULL;
    while (a!=NULL) {
        b = a->next;
        free(a);
        a = b;
    }
    pthread_mutex_destroy(&destroyme->qlock);
    pthread_cond_destroy(&destroyme->q_not_empty);
    pthread_cond_destroy(&destroyme->q_empty);
    free(destroyme->threads);
    free(destroyme);
}
/**
 *
 * @param from_me
 * @param dispatch_to_here
 * @param arg
 */
void dispatch(threadpool* from_me, dispatch_fn dispatch_to_here, void *arg){
    if(from_me->dont_accept)
        return;
    work_t * task=(work_t*) malloc(sizeof (work_t));
    task->routine=dispatch_to_here;
    task->arg=arg;
    task->next=NULL;
    pthread_mutex_lock(&from_me->qlock);
    add_task_to_Q(from_me,task);
    pthread_cond_signal(&from_me->q_not_empty);
    pthread_mutex_unlock(&from_me->qlock);
}
/**
 *
 * @param pool
 * @param task
 */
void add_task_to_Q(threadpool* pool,work_t * task){
    if(pool->qsize==0){
        pool->qhead=task;
        pool->qtail=task;
        pool->qtail->next=NULL;
        pool->qsize++;
        return;
    }
    pool->qtail->next=task;
    pool->qtail=pool->qtail->next;
    pool->qsize++;
}