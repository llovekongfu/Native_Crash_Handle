package com.example.nativecrash;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Looper;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.Charset;
import java.util.Set;

import static android.os.Build.VERSION.SDK_INT;

public class NativeCrashUtil {
    private static String NATIVE_CRASH_FILE_PATH = "sdcard/native/nativeCrashFile.txt";
    static {
        try {
            System.loadLibrary("native_crash");
        } catch (UnsatisfiedLinkError e) {
            e.printStackTrace();
        }
    }

    /**
     * 初始化文件及native接口
     * @param activity
     */
    public void initNativeCrashCollect(Activity activity) {
        if (activity == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && activity.checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
            activity.requestPermissions(new String[]{
                    Manifest.permission.READ_EXTERNAL_STORAGE,
                    Manifest.permission.WRITE_EXTERNAL_STORAGE
            }, 1);
            return;
        }
        try {
            File file = new File(NATIVE_CRASH_FILE_PATH);
            File parentFile = file.getParentFile();
            if (!parentFile.exists()) {
                parentFile.mkdir();
            }
            if (!file.exists()) {
                file.createNewFile();
            }
            init(NATIVE_CRASH_FILE_PATH.getBytes(), NATIVE_CRASH_FILE_PATH.length(), SDK_INT);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 回调函数，获取java崩溃时的java栈
     * @param tid 线程id
     * @return
     */
    public static String getJavaBackTrace(int tid) {
        Thread thread = getJavaThreadByTid(tid);
        if (thread == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("*********java stack************\n");
        StackTraceElement[] elements = thread.getStackTrace();
        for (int i = 0; i < elements.length; i++) {
            sb.append("crash at: " + elements[i].getClassName() + "." + elements[i].getMethodName() + "(" + elements[i].getClassName() + ".java:" + elements[i].getLineNumber() + ")" + "\n");
        }
        return sb.toString();
    }

    private static Thread getJavaThreadByTid(int tid) {
        if (tid > 0) {
            String threadName = getJavaThreadNameById(tid);
            return getJavaThreadByName(threadName);
        }
        return null;
    }

    private static String getJavaThreadNameById(int tid) {
        String strName = "";
        int pid = android.os.Process.myPid();
        if (pid == tid) {
            return "main";
        }
        String pathNameFile = String.format("/proc/%d/task/%d/comm", pid, tid);
        FileInputStream fin = null;
        try {
            fin = new FileInputStream(pathNameFile);
            byte[] byteName = new byte[1024];
            int nSize = fin.read(byteName, 0, 1024);
            String strOrg = new String(byteName, 0, nSize, Charset.forName("UTF-8"));
            int nReturn = strOrg.indexOf('\n');
            if (nReturn >= 0) {
                strName = strOrg.substring(0, nReturn);
            } else {
                strName = strOrg;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return strName;
    }

    private static Thread getJavaThreadByName(String threadName) {
        if ("main".equals(threadName)) {
            return Looper.getMainLooper().getThread();
        } else {
            Set<Thread> threadSet = Thread.getAllStackTraces().keySet();
            for (Thread thread : threadSet) {
                String name = thread.getName();
                if (threadName.equals(name)) {
                    return thread;
                }
            }

        }
        return null;
    }

    native void init(byte[] filePath, int length, int version);

    public native int getStringFromJNI(int index);
}
