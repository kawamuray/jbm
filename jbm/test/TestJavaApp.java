import java.util.concurrent.locks.ReentrantLock;

public class TestJavaApp {
    private static void locker(ReentrantLock lock) throws InterruptedException {
        while (true) {
            lock.lock();
            lock.unlock();
            Thread.sleep(1000);
        }
    }

    public static void main(String[] args) throws InterruptedException {
        ReentrantLock lock = new ReentrantLock();
        Thread th = new Thread(() -> {
            try {
                locker(lock);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        th.setName("LOCKER");
        th.start();

        while (true) {
            lock.lock();
            Thread.sleep(5000);
            lock.unlock();
        }
    }
}
