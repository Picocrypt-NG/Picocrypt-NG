//go:build darwin && cgo

package pcv3publication

/*
#include <sys/types.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

// Unlike Linux libacl, Darwin acl_get_entry returns 0 for an entry and
// -1/EINVAL at the end. Validate the returned ACL before interpreting that
// sentinel; unknown entries/errors never establish privacy.
static int pcv3_check_acl(int fd, int allow_deny_entries) {
    // Query presence separately: a getter's NULL/ENOENT alone must not be
    // confused with an underlying filesystem error while fetching metadata.
    filesec_t security = filesec_init();
    if (security == NULL) return errno ? errno : EIO;
    struct stat metadata;
    int present = 0;
    if (fstatx_np(fd, &metadata, security) != 0 ||
        filesec_query_property(security, FILESEC_ACL, &present) != 0) {
        int saved = errno;
        filesec_free(security);
        return saved ? saved : EIO;
    }
    if (!present) {
        filesec_free(security);
        return 0;
    }
    acl_t acl = NULL;
    if (filesec_get_property(security, FILESEC_ACL, &acl) != 0 || acl == NULL ||
        (void *)acl == _FILESEC_REMOVE_ACL) {
        int saved = errno;
        filesec_free(security);
        return saved ? saved : EIO;
    }
    filesec_free(security);
    if (acl_valid(acl) != 0) {
        int saved = errno;
        acl_free(acl);
        return saved ? saved : EIO;
    }
    acl_entry_t entry;
    int selector = ACL_FIRST_ENTRY;
    for (;;) {
        errno = 0;
        int result = acl_get_entry(acl, selector, &entry);
        int saved = errno;
        if (result != 0) {
            acl_free(acl);
            return result == -1 && saved == EINVAL ? 0 : (saved ? saved : EIO);
        }
        acl_tag_t tag;
        if (!allow_deny_entries || acl_get_tag_type(entry, &tag) != 0 || tag != ACL_EXTENDED_DENY) {
            acl_free(acl);
            return EACCES;
        }
        selector = ACL_NEXT_ENTRY;
    }
}

static int pcv3_clear_private_acl(int fd) {
    acl_t empty = acl_init(0);
    if (empty == NULL) return errno ? errno : EIO;
    int result = acl_set_fd_np(fd, empty, ACL_TYPE_EXTENDED);
    int saved = errno;
    acl_free(empty);
    if (result != 0) return saved ? saved : EIO;
    return pcv3_check_acl(fd, 0);
}
*/
import "C"

import (
	"Picocrypt-NG/internal/fileops"
	"os"
	"runtime"
	"syscall"
)

func privateDirectoryBackendAvailable() bool { return true }

func establishPrivateDirectoryACL(file *os.File) error {
	if file == nil {
		return os.ErrInvalid
	}
	// The caller has already checked exclusive creation, UID, mode and pinned
	// identity. Only that fresh directory may have inherited entries removed.
	fd := file.Fd()
	if fd > 0x7fffffff {
		return os.ErrInvalid
	}
	code := C.pcv3_clear_private_acl(C.int(fd))
	runtime.KeepAlive(file)
	if code != 0 {
		return syscall.Errno(code)
	}
	// Persist the restriction before creating a file that may contain plaintext;
	// a crash must not restore inherited access while retaining newer stage data.
	return fileops.SyncDirectory(file)
}

func directoryACLAllowsTrustedCleanup(file *os.File) bool {
	if file == nil {
		return false
	}
	// Deny-only ACLs cannot add namespace mutation rights to another principal.
	// Allow/unknown entries are conservatively refused; the caller's ACL is never changed.
	fd := file.Fd()
	if fd > 0x7fffffff {
		return false
	}
	code := C.pcv3_check_acl(C.int(fd), 1)
	runtime.KeepAlive(file)
	return code == 0
}

func privateDirectoryParentTrusted(parent *os.File) bool { return trustedCleanupParent(parent) }
