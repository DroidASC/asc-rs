import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.function.IntBinaryOperator;
import java.util.function.Supplier;

// Source of callsites.dex:
//   javac --release 8 -d cls CallSites.java
//   d8 --min-api 26 --release --no-desugaring --lib android.jar --output out cls/*.class
// `--no-desugaring` with min-api 26 keeps the lambdas as invoke-custom
// (LambdaMetafactory call sites) and the MethodHandle call as invoke-polymorphic.
public class CallSites {
    static int add(int a, int b) {
        return a + b;
    }

    static int lambdas(int x) {
        IntBinaryOperator op = (a, b) -> a * b + x;
        Supplier<String> s = String::new;
        return op.applyAsInt(x, 3) + s.get().length();
    }

    static int handles(int x) throws Throwable {
        MethodHandle mh = MethodHandles.lookup().findStatic(CallSites.class, "add", MethodType.methodType(int.class, int.class, int.class));
        return (int) mh.invokeExact(x, 2);
    }
}
