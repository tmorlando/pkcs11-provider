/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "platform/endian.h"

#if 1

#define MUTEX_RAISE_ERROR(_errstr) \
    P11PROV_raise(provctx, ret, "%s %s mutex (errno=%d)", _errstr, obj, err); \
    P11PROV_debug("Called from [%s:%d]%s()", file, line, func)


CK_RV p11prov_mutex_init(P11PROV_CTX *provctx, P11PROV_MUTEX *lock,
                         const char *obj, const char *file, int line,
                         const char *func)
{
    CK_RV ret = CKR_OK;
    int err;

    err = pthread_mutex_init(lock, NULL);
    if (err != 0) {
        err = errno;
        ret = CKR_CANT_LOCK;
        MUTEX_RAISE_ERROR("Failed to init");
    }
    return ret;
}

CK_RV p11prov_mutex_lock(P11PROV_CTX *provctx, P11PROV_MUTEX *lock,
                         const char *obj, const char *file, int line,
                         const char *func)
{
    CK_RV ret = CKR_OK;
    int err;

    err = pthread_mutex_lock(lock);
    if (err != 0) {
        err = errno;
        ret = CKR_CANT_LOCK;
        MUTEX_RAISE_ERROR("Failed to lock");
    }
    return ret;
}

CK_RV p11prov_mutex_unlock(P11PROV_CTX *provctx, P11PROV_MUTEX *lock,
                           const char *obj, const char *file, int line,
                           const char *func)
{
    CK_RV ret = CKR_OK;
    int err;

    err = pthread_mutex_unlock(lock);
    if (err != 0) {
        err = errno;
        ret = CKR_CANT_LOCK;
        MUTEX_RAISE_ERROR("Failed to unlock");
    }
    return ret;
}

CK_RV p11prov_mutex_destroy(P11PROV_CTX *provctx, P11PROV_MUTEX *lock,
                            const char *obj, const char *file, int line,
                            const char *func)
{
    CK_RV ret = CKR_OK;
    int err;

    err = pthread_mutex_destroy(lock);
    if (err != 0) {
        err = errno;
        ret = CKR_CANT_LOCK;
        MUTEX_RAISE_ERROR("Failed to destroy");
    }
    return ret;
}

void p11prov_force_rwlock_reinit(P11PROV_RWLOCK *lock)
{
    pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
    memcpy(lock, &rwlock, sizeof(rwlock));
}

CK_RV p11prov_rwlock_init(P11PROV_RWLOCK *lock)
{
    CK_RV ret = CKR_OK;
    if (pthread_rwlock_init(lock, NULL) != 0) {
      ret = CKR_CANT_LOCK;
    }
    return ret;
}

CK_RV p11prov_rwlock_trywrlock(P11PROV_RWLOCK *lock)
{
    CK_RV ret = CKR_OK;  
    if (pthread_rwlock_trywrlock(lock) != 0) {
      ret = CKR_CANT_LOCK;
    }
    return ret;    
}

CK_RV p11prov_rwlock_rdlock(P11PROV_RWLOCK *lock)
{
    CK_RV ret = CKR_OK;
    if (pthread_rwlock_rdlock(lock) != 0) {
      ret = CKR_CANT_LOCK;      
    }
    return ret;
}

CK_RV p11prov_rwlock_wrlock(P11PROV_RWLOCK *lock)
{
    CK_RV ret = CKR_OK;
    if (pthread_rwlock_wrlock(lock) != 0) {
      ret = CKR_CANT_LOCK;
    }
    return ret;
}

CK_RV p11prov_rwlock_unlock(P11PROV_RWLOCK *lock)
{
    CK_RV ret = CKR_OK;
    if (pthread_rwlock_unlock(lock) != 0) {
      ret = CKR_CANT_LOCK;      
    }
    return ret;
}

CK_RV p11prov_rwlock_destroy(P11PROV_RWLOCK *lock)
{
    CK_RV ret = CKR_OK;
    if (pthread_rwlock_destroy(lock) != 0) {
      ret = CKR_CANT_LOCK;            
    }
    return ret;
}

#else

CK_RV p11prov_mutex_init(P11PROV_CTX *provctx, P11PROV_MUTEX *lock,
                         const char *obj, const char *file, int line,
                         const char *func)
{
    CK_RV ret = CKR_OK;
    InitializeCriticalSection(lock);    
    return ret;
}

CK_RV p11prov_mutex_lock(P11PROV_CTX *provctx, P11PROV_MUTEX *lock,
                         const char *obj, const char *file, int line,
                         const char *func)
{
    CK_RV ret = CKR_OK;
    EnterCriticalSection(lock);    
    return ret;
}

CK_RV p11prov_mutex_unlock(P11PROV_CTX *provctx, P11PROV_MUTEX *lock,
                           const char *obj, const char *file, int line,
                           const char *func)
{
    CK_RV ret = CKR_OK;
    LeaveCriticalSection(lock);    
    return ret;
}

CK_RV p11prov_mutex_destroy(P11PROV_CTX *provctx, P11PROV_MUTEX *lock,
                            const char *obj, const char *file, int line,
                            const char *func)
{
    CK_RV ret = CKR_OK;
    DeleteCriticalSection(lock);    
    return ret;
}

void p11prov_force_rwlock_reinit(P11PROV_RWLOCK *lock)
{
    P11PROV_RWLOCK rwlock;
    p11prov_rwlock_init(&rwlock);
    memcpy(lock, &rwlock, sizeof(rwlock));
}

CK_RV p11prov_rwlock_init(P11PROV_RWLOCK *lock)
{
    CK_RV ret = CKR_OK;
    InitializeSRWLock(&lock->srwlock);
    lock->exclusive = 0;    
    return ret;
}

CK_RV p11prov_rwlock_rdlock(P11PROV_RWLOCK *lock)
{
    CK_RV ret = CKR_OK;
    AcquireSRWLockShared(&lock->srwlock);
    lock->exclusive = 0;
    return ret;
}

CK_RV p11prov_rwlock_trywrlock(P11PROV_RWLOCK *lock)
{
    CK_RV ret = CKR_OK;  
    if (!TryAcquireSRWLockExclusive(&lock->srwlock)) {
      ret = CKR_CANT_LOCK;            
    } else {
      lock->exclusive = 1;      
    }
    return ret;    
}

CK_RV p11prov_rwlock_wrlock(P11PROV_RWLOCK *lock)
{
    CK_RV ret = CKR_OK;
    AcquireSRWLockExclusive(&lock->srwlock);
    lock->exclusive = 1;
    return ret;
}

CK_RV p11prov_rwlock_unlock(P11PROV_RWLOCK *lock)
{
    CK_RV ret = CKR_OK;
    if (lock->exclusive) {
      ReleaseSRWLockExclusive(&lock->srwlock);
    } else {
      ReleaseSRWLockShared(&lock->srwlock);
    }
    lock->exclusive = 0;
    return ret;
}

CK_RV p11prov_rwlock_destroy(P11PROV_RWLOCK *lock)
{
    CK_RV ret = CKR_OK;
    return ret;
}

#endif
