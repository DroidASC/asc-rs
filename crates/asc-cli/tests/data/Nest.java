// Source of nest.dex, a class with an inner class that writes its outer
// instance's field:
//   javac --release 8 -d cls Nest.java
//   d8 --release --lib android.jar --output out cls/*.class
public class Nest {
    private int count;

    class Inner {
        int touch(int i) {
            count = i;
            return count;
        }
    }

    int run() {
        return new Inner().touch(3);
    }
}
