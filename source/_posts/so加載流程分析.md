---
title: so加載流程分析
date: 2024-06-01 16:29:14
tags:
- so文件
categories: Android逆向
keywords:
- so文件
- Android逆向
description: so加載流程分析
cover: Untitled.png
---

## 前言

同樣是在研究360加固，對so加載的理解不夠深刻，特此分析記錄完整的so加載流程。

注：分析的AOSP版本是`Oreo8.1.0_r33`。

## So加載流程

### `System.loadLibrary`與`System.load`

`loadLibrary`：傳入的是一個so的名稱，如`libtest.so`，這個so通常位於`/data/app/<pkg>/lib/<arch>`下。

`load`：傳入的是so的絕對地址。

兩者的執行流程其實沒有太大差異，最終都會調用`Runtime_nativeLoad`，本文以`System.load`作為起始點，一步一步分析下去。

```java
// libcore/ojluni/src/main/java/java/lang/System.java

@CallerSensitive
public static void loadLibrary(String libname) {
    Runtime.getRuntime().loadLibrary0(Reflection.getCallerClass(), libname);
}

@CallerSensitive
public static void load(String filename) {
    Runtime.getRuntime().load0(Reflection.getCallerClass(), filename);
}
```

### `Runtime.load0`

先判斷傳入的`filename`是否絕對地址，然後調用`nativeLoad`。

而`nativeLoad`是個native函數，表示接下來就要開始分析native層代碼。

```java
// libcore/ojluni/src/main/java/java/lang/Runtime.java

synchronized void load0(Class<?> fromClass, String filename) {
    if (!(new File(filename).isAbsolute())) {
        throw new UnsatisfiedLinkError(
            "Expecting an absolute path of the library: " + filename);
    }
    if (filename == null) {
        throw new NullPointerException("filename == null");
    }
    String error = nativeLoad(filename, fromClass.getClassLoader(), fromClass);
    if (error != null) {
        throw new UnsatisfiedLinkError(error);
    }
}

private static native String nativeLoad(String filename, ClassLoader loader, Class<?> caller);
```

### `nativeLoad`

`nativeLoad`是個JNI函數，它采用了靜態注冊+動態注冊。

靜態注冊表現為`JNIEXPORT jstring JNICALL Runtime_nativeLoad`，而動態注冊表現為`jniRegisterNativeMethods`( 這個函數內會調用`RegisterNatives`實現動態注冊 )，不太理解為何要靜態+動態注冊，可能是為了靈活性？

之後繼續深入分析`JVM_NativeLoad`。

```cpp
// libcore/ojluni/src/main/native/Runtime.c

JNIEXPORT jstring JNICALL
Runtime_nativeLoad(JNIEnv* env, jclass ignored, jstring javaFilename,
                   jobject javaLoader, jclass caller)
{
    return JVM_NativeLoad(env, javaFilename, javaLoader, caller);
}

static JNINativeMethod gMethods[] = {
  FAST_NATIVE_METHOD(Runtime, freeMemory, "()J"),
  FAST_NATIVE_METHOD(Runtime, totalMemory, "()J"),
  FAST_NATIVE_METHOD(Runtime, maxMemory, "()J"),
  NATIVE_METHOD(Runtime, nativeGc, "()V"),
  NATIVE_METHOD(Runtime, nativeExit, "(I)V"),
  NATIVE_METHOD(Runtime, nativeLoad,
                "(Ljava/lang/String;Ljava/lang/ClassLoader;Ljava/lang/Class;)"
                    "Ljava/lang/String;"),
};

void register_java_lang_Runtime(JNIEnv* env) {
  jniRegisterNativeMethods(env, "java/lang/Runtime", gMethods, NELEM(gMethods));
}
```

### `JVM_NativeLoad`

`JVM_NativeLoad`調用了`LoadNativeLibrary`，繼續深入`LoadNativeLibrary`

```cpp
// art/runtime/openjdkjvm/OpenjdkJvm.cc

JNIEXPORT jstring JVM_NativeLoad(JNIEnv* env,
                                 jstring javaFilename,
                                 jobject javaLoader,
                                 jclass caller) {
  ScopedUtfChars filename(env, javaFilename);
  if (filename.c_str() == nullptr) {
    return nullptr;
  }

  std::string error_msg;
  {
    art::JavaVMExt* vm = art::Runtime::Current()->GetJavaVM();
    // here
    bool success = vm->LoadNativeLibrary(env,
                                         filename.c_str(),
                                         javaLoader,
                                         caller,
                                         &error_msg);
    if (success) {
      return nullptr;
    }
  }

  // Don't let a pending exception from JNI_OnLoad cause a CheckJNI issue with NewStringUTF.
  env->ExceptionClear();
  return env->NewStringUTF(error_msg.c_str());
}
```

### `LoadNativeLibrary`

如下代碼只截取了比較重要的部分。

整個LoadNativeLibrary主要可以分成3部分：

1. 在加載so前先判斷so是否已被加載，如果是而且classloader也匹配的話，直接返回successfully，不做任何事情( 這部分的具體邏輯不深究，對分析so加載流程的意義不大 )。
2. 調用`OpenNativeLibrary`加載so，後續會詳細分析該函數。
3. 成功加載so後，若對應的`JNI_OnLoad`方法存在，則調用。

```cpp
// art/runtime/java_vm_ext.cc

bool JavaVMExt::LoadNativeLibrary(JNIEnv* env,
                                  const std::string& path,
                                  jobject class_loader,
                                  jclass caller_class,
                                  std::string* error_msg) {

	// 1. 判斷so是否已加載
  // See if we've already loaded this library.  If we have, and the class loader
  // matches, return successfully without doing anything.
  // TODO: for better results we should canonicalize the pathname (or even compare
  // inodes). This implementation is fine if everybody is using System.loadLibrary.
	// some code here...
	
	
  // Open the shared library.  Because we're using a full path, the system
  // doesn't have to search through LD_LIBRARY_PATH.  (It may do so to
  // resolve this library's dependencies though.)

  // Failures here are expected when java.library.path has several entries
  // and we have to hunt for the lib.

  // Below we dlopen but there is no paired dlclose, this would be necessary if we supported
  // class unloading. Libraries will only be unloaded when the reference count (incremented by
  // dlopen) becomes zero from dlclose.

  // Retrieve the library path from the classloader, if necessary.
  ScopedLocalRef<jstring> library_path(env, GetLibrarySearchPath(env, class_loader));

  Locks::mutator_lock_->AssertNotHeld(self);
  const char* path_str = path.empty() ? nullptr : path.c_str();
  bool needs_native_bridge = false;
  char* nativeloader_error_msg = nullptr;
  // 2. 調用OpenNativeLibrary加載so
  void* handle = android::OpenNativeLibrary(
      env,
      runtime_->GetTargetSdkVersion(),
      path_str,
      class_loader,
      (caller_location.empty() ? nullptr : caller_location.c_str()),
      library_path.get(),
      &needs_native_bridge,
      &nativeloader_error_msg);
  VLOG(jni) << "[Call to dlopen(\"" << path << "\", RTLD_NOW) returned " << handle << "]";

  if (handle == nullptr) {
    *error_msg = nativeloader_error_msg;
    android::NativeLoaderFreeErrorMessage(nativeloader_error_msg);
    VLOG(jni) << "dlopen(\"" << path << "\", RTLD_NOW) failed: " << *error_msg;
    return false;
  }

  if (env->ExceptionCheck() == JNI_TRUE) {
    LOG(ERROR) << "Unexpected exception:";
    env->ExceptionDescribe();
    env->ExceptionClear();
  }
  // Create a new entry.
  // TODO: move the locking (and more of this logic) into Libraries.
  bool created_library = false;
  {
    // Create SharedLibrary ahead of taking the libraries lock to maintain lock ordering.
    std::unique_ptr<SharedLibrary> new_library(
        new SharedLibrary(env,
                          self,
                          path,
                          handle,
                          needs_native_bridge,
                          class_loader,
                          class_loader_allocator));

    MutexLock mu(self, *Locks::jni_libraries_lock_);
    library = libraries_->Get(path);
    if (library == nullptr) {  // We won race to get libraries_lock.
      library = new_library.release();
      libraries_->Put(path, library);
      created_library = true;
    }
  }
  if (!created_library) {
    LOG(INFO) << "WOW: we lost a race to add shared library: "
        << "\"" << path << "\" ClassLoader=" << class_loader;
    return library->CheckOnLoadResult();
  }
  VLOG(jni) << "[Added shared library \"" << path << "\" for ClassLoader " << class_loader << "]";

  bool was_successful = false;
  
  
  // 3. 若JNI_OnLoad存在, 則調用
  void* sym = library->FindSymbol("JNI_OnLoad", nullptr, android::kJNICallTypeRegular);
  if (sym == nullptr) {
    VLOG(jni) << "[No JNI_OnLoad found in \"" << path << "\"]";
    was_successful = true;
  } else {
    // Call JNI_OnLoad.  We have to override the current class
    // loader, which will always be "null" since the stuff at the
    // top of the stack is around Runtime.loadLibrary().  (See
    // the comments in the JNI FindClass function.)
    ScopedLocalRef<jobject> old_class_loader(env, env->NewLocalRef(self->GetClassLoaderOverride()));
    self->SetClassLoaderOverride(class_loader);

    VLOG(jni) << "[Calling JNI_OnLoad in \"" << path << "\"]";
    using JNI_OnLoadFn = int(*)(JavaVM*, void*);
    JNI_OnLoadFn jni_on_load = reinterpret_cast<JNI_OnLoadFn>(sym);
    int version = (*jni_on_load)(this, nullptr);

		// ...
  }

  library->SetResult(was_successful);
  return was_successful;
}
```

### `OpenNativeLibrary`

一開始的條件編譯`#if defined(__ANDROID__)`用於判斷當前代碼是否運行在Android平台上，因此分析的目標就是這條分支。

`g_namespaces->FindNamespaceByClassLoader`用於在給定的`class_loader`中查找對應的命名空間( Namespace )。Namespace在Android的作用是實現本地庫的隔離和加載控制，每個命名空間都有自己的本地庫加載路徑和加載策略，**確保在不同的類加載器之間，本地庫的加載是隔離的，不會亙相干擾。**

正常來說`g_namespaces->FindNamespaceByClassLoader`能順利找到對應的命名空間，並且`ns.is_android_namespace()==true`，所以接下來繼續分析`android_dlopen_ext`。

```cpp
// system/core/libnativeloader/native_loader.cpp
void* OpenNativeLibrary(JNIEnv* env,
                        int32_t target_sdk_version,
                        const char* path,
                        jobject class_loader,
                        jstring library_path,
                        bool* needs_native_bridge,
                        std::string* error_msg) {
#if defined(__ANDROID__)
  UNUSED(target_sdk_version);
  if (class_loader == nullptr) {
    *needs_native_bridge = false;
    return dlopen(path, RTLD_NOW);
  }

  std::lock_guard<std::mutex> guard(g_namespaces_mutex);
  NativeLoaderNamespace ns;

  if (!g_namespaces->FindNamespaceByClassLoader(env, class_loader, &ns)) {
    // This is the case where the classloader was not created by ApplicationLoaders
    // In this case we create an isolated not-shared namespace for it.
    if (!g_namespaces->Create(env,
                              target_sdk_version,
                              class_loader,
                              false /* is_shared */,
                              false /* is_for_vendor */,
                              library_path,
                              nullptr,
                              &ns,
                              error_msg)) {
      return nullptr;
    }
  }

  if (ns.is_android_namespace()) {
    android_dlextinfo extinfo;
    extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
    extinfo.library_namespace = ns.get_android_ns();
		// here
    void* handle = android_dlopen_ext(path, RTLD_NOW, &extinfo);
    if (handle == nullptr) {
      *error_msg = dlerror();
    }
    *needs_native_bridge = false;
    return handle;
  } else {
    void* handle = NativeBridgeLoadLibraryExt(path, RTLD_NOW, ns.get_native_bridge_ns());
    if (handle == nullptr) {
      *error_msg = NativeBridgeGetError();
    }
    *needs_native_bridge = true;
    return handle;
  }
//...
}

```

### `android_dlopen_ext`

`android_dlopen_ext`裡調用了`__loader_android_dlopen_ext`。

`__attribute__((__weak__, visibility("default")))`的解釋如下( from GPT )：

- `__weak__`代表函數是一個弱符號，在鏈接過程中，如何存在多個同名的弱符號定義，那麼它們不同引發重定義錯誤，而是會保留最後一個定義的符號。
- `visibility("default")`設置函數的可見性為默認級別，可以使函數在鏈接時可見，可被其他模塊引用和調用。

```cpp
// bionic/libdl/libdl.c

void* android_dlopen_ext(const char* filename, int flag, const android_dlextinfo* extinfo) {
  const void* caller_addr = __builtin_return_address(0);
  return __loader_android_dlopen_ext(filename, flag, extinfo, caller_addr);
}

__attribute__((__weak__, visibility("default")))
void* __loader_android_dlopen_ext(const char* filename,
                                  int flag,
                                  const android_dlextinfo* extinfo,
                                  const void* caller_addr);
```

本想繼續跟`__loader_android_dlopen_ext`，但卻找不到其具體實現的位置。

![Untitled](Untitled.png)

看別人的分析是在`dlfcn.cpp`中找到`__loader_android_dlopen_ext`的，我手動定位到該文件只能找到`__android_dlopen_ext`，但兩者應該是同一個函數？( 只是不清楚它們是如何聯繫起來的 )

### `__android_dlopen_ext`

注：沒有找到`__loader_android_dlopen_ext`，只找到一個很相似的`__android_dlopen_ext`，兩者大概率是同一個函數，所以就從`__android_dlopen_ext`繼續分析。

`__android_dlopen_ext`調用了`dlopen_ext`，`dlopen_ext`中調用了`do_dlopen`。

```cpp
// bionic/linker/dlfcn.cpp

void* __android_dlopen_ext(const char* filename,
                           int flags,
                           const android_dlextinfo* extinfo,
                           const void* caller_addr) {
  return dlopen_ext(filename, flags, extinfo, caller_addr);
}

static void* dlopen_ext(const char* filename,
                        int flags,
                        const android_dlextinfo* extinfo,
                        const void* caller_addr) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);
  g_linker_logger.ResetState();
  void* result = do_dlopen(filename, flags, extinfo, caller_addr);
  if (result == nullptr) {
    __bionic_format_dlerror("dlopen failed", linker_get_error_buffer());
    return nullptr;
  }
  return result;
}
```

### `do_dlopen`

`do_dlopen`函數實現如下，同樣只保留重要部分。

其中有兩個最關鍵部分：

1. `find_library`函數，查找so的並返回`soinfo`，而`soinfo`顯然保存著so的所有信息。
2. `si->call_constructors()`：調用so的初始化函數，即`.init`和`.init_array`( `.init`先調用 )，通常一些檢測的邏輯很喜歡藏在這裡。

```cpp
// bionic/linker/linker.cpp

void* do_dlopen(const char* name, int flags,
                const android_dlextinfo* extinfo,
                const void* caller_addr) {
  std::string trace_prefix = std::string("dlopen: ") + (name == nullptr ? "(nullptr)" : name);
  ScopedTrace trace(trace_prefix.c_str());
  ScopedTrace loading_trace((trace_prefix + " - loading and linking").c_str());
  soinfo* const caller = find_containing_library(caller_addr);
  android_namespace_t* ns = get_caller_namespace(caller);

	// ...
	
  const char* translated_name = name;
	
	// (一些ASAN模式的邏輯, 不重要)...
	
  ProtectedDataGuard guard;
  // 關鍵點1: 查找so
  soinfo* si = find_library(ns, translated_name, flags, extinfo, caller);
  loading_trace.End();

  if (si != nullptr) {
    void* handle = si->to_handle();
    LD_LOG(kLogDlopen,
           "... dlopen calling constructors: realpath=\"%s\", soname=\"%s\", handle=%p",
           si->get_realpath(), si->get_soname(), handle);
    // 關鍵點2: 調用so的初始化函數, 即.init 和 .init_array
    si->call_constructors();
    failure_guard.Disable();
    LD_LOG(kLogDlopen,
           "... dlopen successful: realpath=\"%s\", soname=\"%s\", handle=%p",
           si->get_realpath(), si->get_soname(), handle);
    return handle;
  }

  return nullptr;
}

```

簡單記錄下`call_constructors`，畢竟不是本文的主線：

```cpp
// bionic/linker/linker_soinfo.cpp

void soinfo::call_constructors() {
  if (constructors_called) {
    return;
  }

 //....
 
  // DT_INIT should be called before DT_INIT_ARRAY if both are present.
  // 1. 調用.init
  call_function("DT_INIT", init_func_, get_realpath());
  // 2. 調用.init_array
  call_array("DT_INIT_ARRAY", init_array_, init_array_count_, false, get_realpath());

  if (!is_linker()) {
    bionic_trace_end();
  }
}
```

### `find_library`

`find_library`中調用了`find_libraries`。

```cpp
// bionic/linker/linker.cpp

static soinfo* find_library(android_namespace_t* ns,
                            const char* name, int rtld_flags,
                            const android_dlextinfo* extinfo,
                            soinfo* needed_by) {
  soinfo* si;

  // readers_map is shared across recursive calls to find_libraries.
  // However, the map is not shared across different threads.
  std::unordered_map<const soinfo*, ElfReader> readers_map;
  if (name == nullptr) {
    si = solist_get_somain();
  } else if (!find_libraries(ns,
                             needed_by,
                             &name,
                             1,
                             &si,
                             nullptr,
                             0,
                             rtld_flags,
                             extinfo,
                             false /* add_as_children */,
                             true /* search_linked_namespaces */,
                             readers_map)) {
    return nullptr;
  }

  si->increment_ref_count();

  return si;
}

```

### `find_libraries` ( 分成七部分 )

最終來到`find_libraries`，從源碼自帶的注釋來看，它可分為7個部分，以下是函數的聲明：

```cpp
// bionic/linker/linker.cpp

// add_as_children - add first-level loaded libraries (i.e. library_names[], but
// not their transitive dependencies) as children of the start_with library.
// This is false when find_libraries is called for dlopen(), when newly loaded
// libraries must form a disjoint tree.
bool find_libraries(android_namespace_t* ns,
                    soinfo* start_with,
                    const char* const library_names[],
                    size_t library_names_count,
                    soinfo* soinfos[],
                    std::vector<soinfo*>* ld_preloads,
                    size_t ld_preloads_count,
                    int rtld_flags,
                    const android_dlextinfo* extinfo,
                    bool add_as_children,
                    bool search_linked_namespaces,
                    std::unordered_map<const soinfo*, ElfReader>& readers_map,
                    std::vector<android_namespace_t*>* namespaces);
 
```

**Step 0：準備階段**

`library_names_count`固定為`1`，因此開頭的循環只會執行一次，創建了一個`LoadTask`並push到`load_tasks`中。

然後會為`soinfos`分配內存。

```cpp
// bionic/linker/linker.cpp

// Step 0: prepare.
LoadTaskList load_tasks;

for (size_t i = 0; i < library_names_count; ++i) {
  const char* name = library_names[i];
  load_tasks.push_back(LoadTask::create(name, start_with, ns, &readers_map));
}

// If soinfos array is null allocate one on stack.
// The array is needed in case of failure; for example
// when library_names[] = {libone.so, libtwo.so} and libone.so
// is loaded correctly but libtwo.so failed for some reason.
// In this case libone.so should be unloaded on return.
// See also implementation of failure_guard below.

if (soinfos == nullptr) {
  size_t soinfos_size = sizeof(soinfo*)*library_names_count;
  soinfos = reinterpret_cast<soinfo**>(alloca(soinfos_size));
  memset(soinfos, 0, soinfos_size);
}

// list of libraries to link - see step 2.
size_t soinfos_count = 0;

// 定義了2個作用域保護器, 在當前作用域結束時自動執行指定操作(清場)
auto scope_guard = android::base::make_scope_guard([&]() {
  for (LoadTask* t : load_tasks) {
    LoadTask::deleter(t);
  }
});
auto failure_guard = android::base::make_scope_guard([&]() {
  // Housekeeping
  soinfo_unload(soinfos, soinfos_count);
});

ZipArchiveCache zip_archive_cache;
```

 **Step 1：任務展開，尋找依據庫( so加載關鍵步驟 )**

在Step 0中調用了`LoadTask::create(name, start_with, ns, &readers_map)`來創建任務，然後這裡又獲取了該任務，在創建時傳入了`start_with`作為task的needed_by，因此這裡的`needed_by`與`start_with`相等，而且`add_as_children`為`false`，所以`is_dt_needed`是`false`。

隨後`task`調用`set_extinfo`和`set_dt_needed`將對應屬性置為`extinfo`和`false`。

`find_library_internal`函數是查找so的關鍵函數，留在後面單獨分析。

```cpp
// bionic/linker/linker.cpp

// Step 1: expand the list of load_tasks to include
// all DT_NEEDED libraries (do not load them just yet)
for (size_t i = 0; i<load_tasks.size(); ++i) {
  LoadTask* task = load_tasks[i];
  soinfo* needed_by = task->get_needed_by();

  bool is_dt_needed = needed_by != nullptr && (needed_by != start_with || add_as_children);
  task->set_extinfo(is_dt_needed ? nullptr : extinfo);
  task->set_dt_needed(is_dt_needed);

  // try to find the load.
  // Note: start from the namespace that is stored in the LoadTask. This namespace
  // is different from the current namespace when the LoadTask is for a transitive
  // dependency and the lib that created the LoadTask is not found in the
  // current namespace but in one of the linked namespace.
  if (!find_library_internal(const_cast<android_namespace_t*>(task->get_start_from()),
                             task,
                             &zip_archive_cache,
                             &load_tasks,
                             rtld_flags,
                             search_linked_namespaces || is_dt_needed)) {
    return false;
  }

  soinfo* si = task->get_soinfo();

  if (is_dt_needed) {
    needed_by->add_child(si);

    if (si->is_linked()) {
      si->increment_ref_count();
    }
  }

  // When ld_preloads is not null, the first
  // ld_preloads_count libs are in fact ld_preloads.
  if (ld_preloads != nullptr && soinfos_count < ld_preloads_count) {
    ld_preloads->push_back(si);
  }

  if (soinfos_count < library_names_count) {
    soinfos[soinfos_count++] = si;
  }
}
```

**Step 2：亂序加載libraries**

這裡的libraries應該是指Step 1中新增的那些依據庫，這裡亂序加載的目的好像是為了防攻擊？

```cpp
// bionic/linker/linker.cpp

// Step 2: Load libraries in random order (see b/24047022)
LoadTaskList load_list;
for (auto&& task : load_tasks) {
  soinfo* si = task->get_soinfo();
  auto pred = [&](const LoadTask* t) {
    return t->get_soinfo() == si;
  };

  if (!si->is_linked() &&
      std::find_if(load_list.begin(), load_list.end(), pred) == load_list.end() ) {
    load_list.push_back(task);
  }
}
shuffle(&load_list);

for (auto&& task : load_list) {
  if (!task->load()) {
    return false;
  }
}
```

**Step 3：按BFS( 廣度優先 )來預鏈接所有共享庫**

調用`prelink_image`來實現預鏈接

```cpp
// bionic/linker/linker.cpp

// Step 3: pre-link all DT_NEEDED libraries in breadth first order.
for (auto&& task : load_tasks) {
  soinfo* si = task->get_soinfo();
  if (!si->is_linked() && !si->prelink_image()) {
    return false;
  }
}

```

`prelink_image`函數如下，預鏈接的主要工作是解析`.dynamic`節。

```cpp
// bionic/linker/linker.cpp

bool soinfo::prelink_image() {
  /* Extract dynamic section */
  ElfW(Word) dynamic_flags = 0;
  phdr_table_get_dynamic_section(phdr, phnum, load_bias, &dynamic, &dynamic_flags);

  /* We can't log anything until the linker is relocated */
  bool relocating_linker = (flags_ & FLAG_LINKER) != 0;
  if (!relocating_linker) {
    INFO("[ Linking \"%s\" ]", get_realpath());
    DEBUG("si->base = %p si->flags = 0x%08x", reinterpret_cast<void*>(base), flags_);
  }

  if (dynamic == nullptr) {
    if (!relocating_linker) {
      DL_ERR("missing PT_DYNAMIC in \"%s\"", get_realpath());
    }
    return false;
  } else {
    if (!relocating_linker) {
      DEBUG("dynamic = %p", dynamic);
    }
  }
	
	// 1. 解析.dynamic節
  // Extract useful information from dynamic section.
  // Note that: "Except for the DT_NULL element at the end of the array,
  // and the relative order of DT_NEEDED elements, entries may appear in any order."
  //
  // source: http://www.sco.com/developers/gabi/1998-04-29/ch5.dynamic.html
  uint32_t needed_count = 0;
  for (ElfW(Dyn)* d = dynamic; d->d_tag != DT_NULL; ++d) {
    DEBUG("d = %p, d[0](tag) = %p d[1](val) = %p",
          d, reinterpret_cast<void*>(d->d_tag), reinterpret_cast<void*>(d->d_un.d_val));
    switch (d->d_tag) {
      case DT_SONAME:
        // this is parsed after we have strtab initialized (see below).
        break;

      case DT_HASH:
        nbucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[0];
        nchain_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[1];
        bucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr + 8);
        chain_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr + 8 + nbucket_ * 4);
        break;

      case DT_GNU_HASH:
        gnu_nbucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[0];
        // skip symndx
        gnu_maskwords_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[2];
        gnu_shift2_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[3];

        gnu_bloom_filter_ = reinterpret_cast<ElfW(Addr)*>(load_bias + d->d_un.d_ptr + 16);
        gnu_bucket_ = reinterpret_cast<uint32_t*>(gnu_bloom_filter_ + gnu_maskwords_);
        // amend chain for symndx = header[1]
        gnu_chain_ = gnu_bucket_ + gnu_nbucket_ -
            reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[1];

        if (!powerof2(gnu_maskwords_)) {
          DL_ERR("invalid maskwords for gnu_hash = 0x%x, in \"%s\" expecting power to two",
              gnu_maskwords_, get_realpath());
          return false;
        }
        --gnu_maskwords_;

        flags_ |= FLAG_GNU_HASH;
        break;

      case DT_STRTAB:
        strtab_ = reinterpret_cast<const char*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_STRSZ:
        strtab_size_ = d->d_un.d_val;
        break;

      case DT_SYMTAB:
        symtab_ = reinterpret_cast<ElfW(Sym)*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_SYMENT:
        if (d->d_un.d_val != sizeof(ElfW(Sym))) {
          DL_ERR("invalid DT_SYMENT: %zd in \"%s\"",
              static_cast<size_t>(d->d_un.d_val), get_realpath());
          return false;
        }
        break;
				// ...
    }
  }

  // 完整性檢測
  if (relocating_linker && needed_count != 0) {
    DL_ERR("linker cannot have DT_NEEDED dependencies on other libraries");
    return false;
  }
  if (nbucket_ == 0 && gnu_nbucket_ == 0) {
    DL_ERR("empty/missing DT_HASH/DT_GNU_HASH in \"%s\" "
        "(new hash type from the future?)", get_realpath());
    return false;
  }
  if (strtab_ == 0) {
    DL_ERR("empty/missing DT_STRTAB in \"%s\"", get_realpath());
    return false;
  }
  if (symtab_ == 0) {
    DL_ERR("empty/missing DT_SYMTAB in \"%s\"", get_realpath());
    return false;
  }
	
	// 2. 根據上述解析好的strtab表來解析DT_SONAME、DT_RUNPATH
  // second pass - parse entries relying on strtab
  for (ElfW(Dyn)* d = dynamic; d->d_tag != DT_NULL; ++d) {
    switch (d->d_tag) {
      case DT_SONAME:
        set_soname(get_string(d->d_un.d_val));
        break;
      case DT_RUNPATH:
        set_dt_runpath(get_string(d->d_un.d_val));
        break;
    }
  }

  // ...
  return true;
}

```

**Step 4：構建global group**

global group是一組具有`DF_1_GLOBAL`標誌的共享庫，這些庫在加載過程中被確定為全局可見的。

1. 對於由環境變量`LD_PRELOAD`指定的庫，將強制設置`DF_1_GLOBAL`位，確保能夠在全局範圍被訪問。
2. 收集在此次運行中新加載的具有`DF_1_GLOBAL`標誌的庫，這些庫將成為global group的新成員。
3. 將新的global group成員添加到所有鏈接的命名空間中，具體是將每個`new_global_group_members`中的成員添加到除了其主要命名空間之外的所有鏈接命名空間。

```cpp
// bionic/linker/linker.cpp

// Step 4: Construct the global group. Note: DF_1_GLOBAL bit of a library is
// determined at step 3.

// Step 4-1: DF_1_GLOBAL bit is force set for LD_PRELOADed libs because they
// must be added to the global group
if (ld_preloads != nullptr) {
  for (auto&& si : *ld_preloads) {
    si->set_dt_flags_1(si->get_dt_flags_1() | DF_1_GLOBAL);
  }
}

// Step 4-2: Gather all DF_1_GLOBAL libs which were newly loaded during this
// run. These will be the new member of the global group
soinfo_list_t new_global_group_members;
for (auto&& task : load_tasks) {
  soinfo* si = task->get_soinfo();
  if (!si->is_linked() && (si->get_dt_flags_1() & DF_1_GLOBAL) != 0) {
    new_global_group_members.push_back(si);
  }
}

// Step 4-3: Add the new global group members to all the linked namespaces
for (auto si : new_global_group_members) {
  for (auto linked_ns : *namespaces) {
    if (si->get_primary_namespace() != linked_ns) {
      linked_ns->add_soinfo(si);
      si->add_secondary_namespace(linked_ns);
    }
  }
}
```

**Step 5：鏈接那些不屬於當前namespace的庫**

通過遞歸調用`find_libraries`來鏈接那些不屬於當前namespace的庫( 從Step 1中找到的 )

```cpp
// bionic/linker/linker.cpp

// Step 5: link libraries that are not destined to this namespace.
// Do this by recursively calling find_libraries on the namespace where the lib
// was found during Step 1.
for (auto&& task : load_tasks) {
  soinfo* si = task->get_soinfo();
  if (si->get_primary_namespace() != ns) {
    const char* name = task->get_name();
    if (find_libraries(si->get_primary_namespace(), task->get_needed_by(), &name, 1,
                       nullptr /* soinfos */, nullptr /* ld_preloads */, 0 /* ld_preload_count */,
                       rtld_flags, nullptr /* extinfo */, false /* add_as_children */,
                       false /* search_linked_namespaces */, readers_map, namespaces)) {
      // If this lib is directly needed by one of the libs in this namespace,
      // then increment the count
      soinfo* needed_by = task->get_needed_by();
      if (needed_by != nullptr && needed_by->get_primary_namespace() == ns && si->is_linked()) {
        si->increment_ref_count();
      }
    } else {
      return false;
    }
  }
}
```

**Step 6：鏈接當前namespace的librarie**

```cpp
// Step 6: link libraries in this namespace
soinfo_list_t local_group;
walk_dependencies_tree(
    (start_with != nullptr && add_as_children) ? &start_with : soinfos,
    (start_with != nullptr && add_as_children) ? 1 : soinfos_count,
    [&] (soinfo* si) {
  if (ns->is_accessible(si)) {
    local_group.push_back(si);
    return kWalkContinue;
  } else {
    return kWalkSkip;
  }
});

soinfo_list_t global_group = ns->get_global_group();
bool linked = local_group.visit([&](soinfo* si) {
  if (!si->is_linked()) {
    if (!si->link_image(global_group, local_group, extinfo) ||
        !get_cfi_shadow()->AfterLoad(si, solist_get_head())) {
      return false;
    }
  }

  return true;
});

if (linked) {
  local_group.for_each([](soinfo* si) {
    if (!si->is_linked()) {
      si->set_linked();
    }
  });

  failure_guard.Disable();
}

return linked;
```

### `find_library_internal`

從上述Step 1中的`find_library_internal`繼續分析，大致流程如下：

1. 調用`find_loaded_library_by_soname`判斷so是否已被加載。
2. 確認未曾加載過該so後，調用`load_library`來正式加載。
3. 若在第2步中找不到，則嘗試在linked namespaces裡查找。

```cpp
// bionic/linker/linker.cpp

static bool find_library_internal(android_namespace_t* ns,
                                  LoadTask* task,
                                  ZipArchiveCache* zip_archive_cache,
                                  LoadTaskList* load_tasks,
                                  int rtld_flags,
                                  bool search_linked_namespaces) {
  soinfo* candidate;
	// 判斷so是否已被加載
  if (find_loaded_library_by_soname(ns, task->get_name(), search_linked_namespaces, &candidate)) {
    task->set_soinfo(candidate);
    return true;
  }

  // Library might still be loaded, the accurate detection
  // of this fact is done by load_library.
  TRACE("[ \"%s\" find_loaded_library_by_soname failed (*candidate=%s@%p). Trying harder...]",
      task->get_name(), candidate == nullptr ? "n/a" : candidate->get_realpath(), candidate);
	// 關鍵點here
  if (load_library(ns, task, zip_archive_cache, load_tasks, rtld_flags, search_linked_namespaces)) {
    return true;
  }
	
	// 當指定so沒有找到時, 會嘗試在linked namespaces裡查找
  if (search_linked_namespaces) {
    // if a library was not found - look into linked namespaces
    for (auto& linked_namespace : ns->linked_namespaces()) {
      if (find_library_in_linked_namespace(linked_namespace,
                                           task)) {
        if (task->get_soinfo() == nullptr) {
          // try to load the library - once namespace boundary is crossed
          // we need to load a library within separate load_group
          // to avoid using symbols from foreign namespace while.
          //
          // However, actual linking is deferred until when the global group
          // is fully identified and is applied to all namespaces.
          // Otherwise, the libs in the linked namespace won't get symbols from
          // the global group.
          if (load_library(linked_namespace.linked_namespace(), task, zip_archive_cache, load_tasks, rtld_flags, false)) {
            return true;
          }
          // lib was not found in the namespace. Try next linked namespace.
        } else {
          // lib is already loaded
          return true;
        }
      }
    }
  }

  return false;
}
```

### `load_library`

繼續深入`load_library`：

1. `extinfo->flags`根據上方記錄的調用棧來看是`ANDROID_DLEXT_USE_NAMESPACE`，而`ANDROID_DLEXT_USE_LIBRARY_FD`的值如下，兩者`&`的結果是`0`，因此不會走if分支。根據大佬的分析，這個if語句存在的意義是提高運行效率，一些底層的庫已被加載過，那麼就沒有必要再打開，搜索一次，直接把library的`fd`拿過來用就可以了。
2. `open_library`打開指定so文件，就是在這個函數中調用最基礎的`open`函數來打開文件，並且返回`fd`。
3. 調用另一個重載的`load_library`。

```cpp
// external/libmojo/base/android/linker/android_dlext.h
ANDROID_DLEXT_USE_LIBRARY_FD = 0x10
// bionic/libc/include/android/dlext.h
ANDROID_DLEXT_USE_NAMESPACE = 0x200

// bionic/linker/linker.cpp

static bool load_library(android_namespace_t* ns,
                         LoadTask* task,
                         ZipArchiveCache* zip_archive_cache,
                         LoadTaskList* load_tasks,
                         int rtld_flags,
                         bool search_linked_namespaces) {
  const char* name = task->get_name();
  soinfo* needed_by = task->get_needed_by();
  const android_dlextinfo* extinfo = task->get_extinfo();

  off64_t file_offset;
  std::string realpath;
  // 1. 提高運行效率，一些底層的庫已被加載過，那麼就沒有必要再打開，搜索一次，直接把library的fd拿過來用就可以了
  if (extinfo != nullptr && (extinfo->flags & ANDROID_DLEXT_USE_LIBRARY_FD) != 0) {
    file_offset = 0;
    if ((extinfo->flags & ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET) != 0) {
      file_offset = extinfo->library_fd_offset;
    }

    if (!realpath_fd(extinfo->library_fd, &realpath)) {
      PRINT("warning: unable to get realpath for the library \"%s\" by extinfo->library_fd. "
            "Will use given name.", name);
      realpath = name;
    }

    task->set_fd(extinfo->library_fd, false);
    task->set_file_offset(file_offset);
    return load_library(ns, task, load_tasks, rtld_flags, realpath, search_linked_namespaces);
  }
	
	// 2. 正式打開指定so文件
  // Open the file.
  int fd = open_library(ns, zip_archive_cache, name, needed_by, &file_offset, &realpath);
  if (fd == -1) {
    DL_ERR("library \"%s\" not found", name);
    return false;
  }

  task->set_fd(fd, true);
  task->set_file_offset(file_offset);
	
	// 3. 調用另一個重載的load_library
  return load_library(ns, task, load_tasks, rtld_flags, realpath, search_linked_namespaces);
}

```

`open_library`函數如下，在這裡會正式調用`open`來打開文件，並且返回對應的文件描述符

```cpp
// bionic/linker/linker.cpp
static int open_library(android_namespace_t* ns,
                        ZipArchiveCache* zip_archive_cache,
                        const char* name, soinfo *needed_by,
                        off64_t* file_offset, std::string* realpath) {
  TRACE("[ opening %s at namespace %s]", name, ns->get_name());

  // If the name contains a slash, we should attempt to open it directly and not search the paths.
  // 1. 判斷name是否包含'/', 是則進入該if分支
  if (strchr(name, '/') != nullptr) {
    int fd = -1;
		
		// kZipFileSeparator == "!/", 顯然name中沒有kZipFileSeparator, 因此不會走這條分支
    if (strstr(name, kZipFileSeparator) != nullptr) {
      fd = open_library_in_zipfile(zip_archive_cache, name, file_offset, realpath);
    }

    if (fd == -1) {
	    // 2. 正式調用open打開文件
      fd = TEMP_FAILURE_RETRY(open(name, O_RDONLY | O_CLOEXEC));
      if (fd != -1) {
        *file_offset = 0;
        if (!realpath_fd(fd, realpath)) {
          PRINT("warning: unable to get realpath for the library \"%s\". Will use given path.", name);
          *realpath = name;
        }
      }
    }
		// 3. 返回文件描述符
    return fd;
  }
	// ...
  
}
```

### `load_library`( 重載版本 )

上述的`load_library`最後調用了如下重載的`load_library`，大致執行流程如下：

1. 一開始先校驗so文件的各種屬性是否符合規範。
2. `extinfo->flags & ANDROID_DLEXT_FORCE_LOAD`的結果是`0`，會走該if分支。調用`find_loaded_library_by_inode`在給定的命名空間中查找已加載的庫，並根據不同的條件判斷是否可以直接返回已加載的庫。
3. 正式開始讀取so文件的elf header和一些segment，遍歷`.dynamic`節讀取`DT_RUNPATH`( so文件的運行路徑 )、`DT_SONAME`( so文件名 )、`DT_NEEDED`( so文件的依據庫 )，通通都會保存在`si`( `soinfo`結構體 )中。

```cpp
// bionic/linker/linker.cpp

static bool load_library(android_namespace_t* ns,
                         LoadTask* task,
                         LoadTaskList* load_tasks,
                         int rtld_flags,
                         const std::string& realpath,
                         bool search_linked_namespaces) {
  off64_t file_offset = task->get_file_offset();
  const char* name = task->get_name();
  const android_dlextinfo* extinfo = task->get_extinfo();
	// 1. 校驗so文件的各種屬性是否符合規範
  //...
  
  // Check for symlink and other situations where
  // file can have different names, unless ANDROID_DLEXT_FORCE_LOAD is set
  if (extinfo == nullptr || (extinfo->flags & ANDROID_DLEXT_FORCE_LOAD) == 0) {
    soinfo* si = nullptr;
    // 2. 在給定的命名空間中查找已加載的庫，並根據不同的條件判斷是否可以直接返回已加載的庫。
    if (find_loaded_library_by_inode(ns, file_stat, file_offset, search_linked_namespaces, &si)) {
      TRACE("library \"%s\" is already loaded under different name/path \"%s\" - "
            "will return existing soinfo", name, si->get_realpath());
      task->set_soinfo(si);
      return true;
    }
  }

	//...

  soinfo* si = soinfo_alloc(ns, realpath.c_str(), &file_stat, file_offset, rtld_flags);
  if (si == nullptr) {
    return false;
  }

  task->set_soinfo(si);
	
	// 3. 正式開始讀取so文件
  // Read the ELF header and some of the segments.
  if (!task->read(realpath.c_str(), file_stat.st_size)) {
    soinfo_free(si);
    task->set_soinfo(nullptr);
    return false;
  }

  // find and set DT_RUNPATH and dt_soname
  // Note that these field values are temporary and are
  // going to be overwritten on soinfo::prelink_image
  // with values from PT_LOAD segments.
  const ElfReader& elf_reader = task->get_elf_reader();
  for (const ElfW(Dyn)* d = elf_reader.dynamic(); d->d_tag != DT_NULL; ++d) {
	// 在.dynamic節找當前so的運行路徑和文件名
    if (d->d_tag == DT_RUNPATH) {
      si->set_dt_runpath(elf_reader.get_string(d->d_un.d_val));
    }
    if (d->d_tag == DT_SONAME) {
      si->set_soname(elf_reader.get_string(d->d_un.d_val));
    }
  }
	// 在.dynamic節找所有的依據庫
  for_each_dt_needed(task->get_elf_reader(), [&](const char* name) {
    load_tasks->push_back(LoadTask::create(name, si, ns, task->get_readers_map()));
  });

  return true;
}

```

## 要點記錄

記錄一些Android逆向要特別關注的點：

```
- System.loadLibrary()
		- Runtime.loadLibrary()
				- Runtime.doLoad()
			      - Runtime_nativeLoad()
		        - LoadNativeLibrary()
			        - android_dlopen_ext()
	              - do_dlopen()  // 打開動態庫
									- .init()  // 初始化,通常一些反調試、檢測、ollvm字符加解密可能會在這裡
									- .initarray() // 同理
              - dlsym()  // 獲取方法指針( 會獲取JNI_OnLoad的方法指針 )
              - JNI_OnLoad() // 根據從dlsym獲取的方法指針,執行JNI_OnLoad
```

- `System.loadLibrary`和`System.load`都可以用來加載so，區別是`loadLibrary`可以自動載入依賴庫，而`load`要指定特定路徑的動態庫
- 對於`loadLibrary`會將`xxx`動態庫的名字轉換為`libxxx.so`，再從`/data/app/[packagename]-1/lib/arm64`，`/vendor/lib64`，`/system/lib64`等路徑查詢對應的動態庫。
- 無論哪種方式，最終都會呼叫到`LoadNativeLibrary`方法，該方法主要操作：
    - 透過`dlopen`開啟動態共享庫
    - 透過`dlsym`取得`JNI_OnLoad`符號所對應的方法
    - 呼叫該載入庫中的`JNI_OnLoad`方法
- 在`android_dlopen_ext`( android8後叫`dlopen_ext` )調用完成後，so其實已經加載、初始化完畢

`dlopen` 和 `dlsym` 的簡易例子( only for 理解，非實際例子 )：

```cpp
int main() {
	//1.打开动态库，拿到一个动态库句柄
	void* handle = dlopen(LIB_PATH, RTLD_NOW);
  //2.通过句柄和方法名获取方法指针地址
	symAdd = dlsym(handle, "add");
  //3.将方法地址强制类型转换成方法指针
	CACULATE_FUNC addFunc = reinterpret_cast(symAdd);
  //4.调用动态库中的方法
	cout << "1 + 2 = " << addFunc(1, 2) << endl;
  //5.通过句柄关闭动态库
	dlclose(handle);
	return 0;
}
```

## 資料

- [https://oacia.dev/android-load-so/](https://oacia.dev/android-load-so/)
- [https://cloud.tencent.com/developer/article/1563054](https://cloud.tencent.com/developer/article/1563054)
- [https://www.cnblogs.com/runope/p/14789784.html](https://www.cnblogs.com/runope/p/14789784.html)
- [https://bbs.kanxue.com/thread-255674.htm](https://bbs.kanxue.com/thread-255674.htm)