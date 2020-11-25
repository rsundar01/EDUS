package com.security.cryptoutility;

/**
 * Created by cloudera on 11/23/16.
 */
interface PriorityRunnable extends Runnable, Comparable<PriorityRunnable> {

    public void setPriority(int priority);

    public int getPriority();
}
