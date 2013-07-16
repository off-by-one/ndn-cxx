/**
 * @author: Jeff Thompson
 * This is a port of py from PyCCN, written by: 
 * Derek Kulinski <takeda@takeda.tk>
 * Jeff Burke <jburke@ucla.edu>
 * 
 * See COPYING for copyright and distribution information.
 */

#ifndef NDN_CLOSURE_HPP
#define	NDN_CLOSURE_HPP

#include "Common.hpp"

namespace ndn {

enum UpcallResult {
  CLOSURE_RESULT_ERR               = -1, // upcall detected an error
  CLOSURE_RESULT_OK                =  0, // normal upcall return
  CLOSURE_RESULT_REEXPRESS         =  1, // reexpress the same interest again
  CLOSURE_RESULT_INTEREST_CONSUMED =  2, // upcall claims to consume interest
  CLOSURE_RESULT_VERIFY            =  3, // force an unverified result to be verified
  CLOSURE_RESULT_FETCHKEY          =  4  // get the key in the key locator and re-call the interest
};

enum UpcallKind {
  UPCALL_FINAL              = 0, // handler is about to be deregistered
  UPCALL_INTEREST           = 1, // incoming interest
  UPCALL_CONSUMED_INTEREST  = 2, // incoming interest, someone has answered
  UPCALL_CONTENT            = 3, // incoming verified content
  UPCALL_INTEREST_TIMED_OUT = 4, // interest timed out
  UPCALL_CONTENT_UNVERIFIED = 5, // content that has not been verified
  UPCALL_CONTENT_BAD        = 6  // verification failed  
};

class NDN;
class Interest;
class ContentObject;

class UpcallInfo {
public:
  UpcallInfo(NDN *ndn, ptr_lib::shared_ptr<Interest> interest, int matchedComps, ptr_lib::shared_ptr<ContentObject> contentObject) 
  {
    ndn_ = ndn;
    interest_ = interest;
    contentObject_ = contentObject;
  }
  
  NDN *getNDN() { return ndn_; }
  
  ptr_lib::shared_ptr<Interest> getInterest() { return interest_; }
  
  ptr_lib::shared_ptr<ContentObject> getContentObject() { return contentObject_; }
  
private:
  NDN *ndn_;
  ptr_lib::shared_ptr<Interest> interest_;
  ptr_lib::shared_ptr<ContentObject> contentObject_;
};

class Closure {
public:
  virtual UpcallResult upcall(UpcallKind kind, UpcallInfo &upcallInfo) = 0;
};

}

#endif