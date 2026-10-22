import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Random;
import java.util.TreeMap;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class LogAnalysisAssignment {

    public record LogEntry(
            String method,
            String path,
            int status,
            long responseBytes,
            long durationMillis
    ) {}

    public record LogFile(Path path) {}

    public record PathStatistics(
            long requests,
            long successful,
            long errors,
            long responseBytes,
            long totalDurationMillis,
            long maxDurationMillis
    ) {}

    public record Report(
            long totalRequests,
            long successfulRequests,
            long errorRequests,
            long responseBytes,
            long maxDurationMillis
    ) {}

    public static final class LogFileLines {
        private LogFileLines() {}

        public static Iterator<String> iterator(Path path) {
            try {
                BufferedReader reader = Files.newBufferedReader(
                        path,
                        StandardCharsets.UTF_8
                );

                return new Iterator<>() {
                    private String nextLine = readNext();
                    private boolean closed;

                    private String readNext() {
                        try {
                            String line = reader.readLine();
                            if (line == null) {
                                close();
                            }
                            return line;
                        } catch (IOException exception) {
                            close();
                            throw new RuntimeException(
                                    "Cannot read " + path,
                                    exception
                            );
                        }
                    }

                    private void close() {
                        if (closed) {
                            return;
                        }
                        closed = true;
                        try {
                            reader.close();
                        } catch (IOException exception) {
                            throw new RuntimeException(
                                    "Cannot close " + path,
                                    exception
                            );
                        }
                    }

                    @Override
                    public boolean hasNext() {
                        return nextLine != null;
                    }

                    @Override
                    public String next() {
                        if (nextLine == null) {
                            throw new NoSuchElementException();
                        }
                        String result = nextLine;
                        nextLine = readNext();
                        return result;
                    }
                };
            } catch (IOException exception) {
                throw new RuntimeException(
                        "Cannot open " + path,
                        exception
                );
            }
        }
    }

    public static final class GenerateLogs {
        private static final String[] METHODS = {
                "GET", "POST", "PUT", "DELETE"
        };
        private static final String[] PATHS = {
                "/", "/index.html", "/login", "/api/users",
                "/api/orders", "/api/products", "/search", "/health"
        };
        private static final int[] STATUSES = {
                200, 200, 200, 201, 204,
                301, 400, 401, 404, 500
        };

        private GenerateLogs() {}

        public static void generate(
                Path outputDirectory,
                int fileCount,
                int linesPerFile
        ) throws IOException {
            if (fileCount < 0 || linesPerFile < 0) {
                throw new IllegalArgumentException(
                        "Counts must be non-negative"
                );
            }

            Files.createDirectories(outputDirectory);
            Random random = new Random(42);

            for (int fileId = 0; fileId < fileCount; fileId++) {
                Path file = outputDirectory.resolve(
                        "access-%03d.log".formatted(fileId)
                );

                try (BufferedWriter writer = Files.newBufferedWriter(
                        file,
                        StandardCharsets.UTF_8
                )) {
                    for (int line = 0; line < linesPerFile; line++) {
                        String method =
                                METHODS[random.nextInt(METHODS.length)];
                        String path =
                                PATHS[random.nextInt(PATHS.length)];
                        int status =
                                STATUSES[random.nextInt(STATUSES.length)];
                        long responseBytes =
                                100L + random.nextInt(100_000);
                        long durationMillis =
                                1L + random.nextInt(500);

                        writer.write(
                                "%s %s %d %d %d%n".formatted(
                                        method,
                                        path,
                                        status,
                                        responseBytes,
                                        durationMillis
                                )
                        );
                    }
                }
            }
        }
    }

    // 1. Разбор строки

    static LogEntry parseLine(String line) {
        String[] parts = line.trim().split("\\s+");
        if (parts.length != 5) {
            throw new IllegalArgumentException(
                    "Нужно 5 полей, а в строке " + parts.length
                            + ": \"" + line + "\"");
        }

        int status;
        long bytes;
        long duration;
        try {
            status = Integer.parseInt(parts[2]);
            bytes = Long.parseLong(parts[3]);
            duration = Long.parseLong(parts[4]);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "Плохое число в строке: \"" + line + "\"", e);
        }

        if (status < 200 || status > 599) {
            throw new IllegalArgumentException(
                    "Неправильный статус " + status + ": \"" + line + "\"");
        }
        if (bytes < 0 || duration < 0) {
            throw new IllegalArgumentException(
                    "Отрицательное число в строке: \"" + line + "\"");
        }
        return new LogEntry(parts[0], parts[1], status, bytes, duration);
    }

    static boolean isSuccess(int status) {
        return status >= 200 && status <= 399;
    }

    // Результат анализа

    public record Result(
            Report report,
            Map<String, PathStatistics> byPath,
            int processedFiles,
            int stoppedFiles,
            int failedFiles,
            List<String> failedNames,
            long readLines,
            long validEntries,
            long corruptedLines,
            int maxActiveFiles,
            int activeFilesAtEnd,
            boolean stopRequested
    ) {}

    static Report buildReport(Map<String, PathStatistics> byPath) {
        long requests = 0;
        long ok = 0;
        long err = 0;
        long bytes = 0;
        long max = 0;
        for (PathStatistics s : byPath.values()) {
            requests += s.requests();
            ok += s.successful();
            err += s.errors();
            bytes += s.responseBytes();
            max = Math.max(max, s.maxDurationMillis());
        }
        return new Report(requests, ok, err, bytes, max);
    }

    // 2. Последовательный отчёт

    static Result analyzeSequential(List<LogFile> files) {
        Map<String, UrlStats> stats = new HashMap<>();
        List<String> failed = new ArrayList<>();
        int processed = 0;
        long lines = 0;
        long valid = 0;
        long bad = 0;

        for (LogFile file : files) {
            try {
                Iterator<String> it = LogFileLines.iterator(file.path());
                while (it.hasNext()) {
                    String line = it.next();
                    lines++;
                    try {
                        LogEntry entry = parseLine(line);
                        UrlStats st = stats.get(entry.path());
                        if (st == null) {
                            st = new UrlStats();
                            stats.put(entry.path(), st);
                        }
                        st.add(entry);
                        valid++;
                    } catch (IllegalArgumentException ex) {
                        bad++;
                    }
                }
                processed++;
            } catch (RuntimeException ex) {
                failed.add(file.path().getFileName() + ": " + ex.getMessage());
            }
        }

        Map<String, PathStatistics> byPath = new HashMap<>();
        for (Map.Entry<String, UrlStats> e : stats.entrySet()) {
            byPath.put(e.getKey(), e.getValue().snapshot());
        }
        return new Result(buildReport(byPath), byPath, processed, 0,
                failed.size(), failed, lines, valid, bad,
                files.isEmpty() ? 0 : 1, 0, false);
    }

    // 4. Потокобезопасная статистика

    interface StatsAccumulator {
        void add(LogEntry entry);

        Map<String, PathStatistics> snapshot();
    }

    // статистика одного URL, методы synchronized
    static final class UrlStats {
        private long requests;
        private long successful;
        private long errors;
        private long responseBytes;
        private long totalDuration;
        private long maxDuration;

        synchronized void add(LogEntry e) {
            requests++;
            if (isSuccess(e.status())) {
                successful++;
            } else {
                errors++;
            }
            responseBytes += e.responseBytes();
            totalDuration += e.durationMillis();
            if (e.durationMillis() > maxDuration) {
                maxDuration = e.durationMillis();
            }
        }

        synchronized PathStatistics snapshot() {
            return new PathStatistics(requests, successful, errors,
                    responseBytes, totalDuration, maxDuration);
        }
    }

    static final class GlobalLockAccumulator implements StatsAccumulator {
        private final Map<String, UrlStats> map = new HashMap<>();

        @Override
        public synchronized void add(LogEntry entry) {
            UrlStats s = map.get(entry.path());
            if (s == null) {
                s = new UrlStats();
                map.put(entry.path(), s);
            }
            s.add(entry);
        }

        @Override
        public synchronized Map<String, PathStatistics> snapshot() {
            Map<String, PathStatistics> result = new HashMap<>();
            for (Map.Entry<String, UrlStats> e : map.entrySet()) {
                result.put(e.getKey(), e.getValue().snapshot());
            }
            return result;
        }
    }

    static final class PerUrlAccumulator implements StatsAccumulator {
        private final ConcurrentHashMap<String, UrlStats> map =
                new ConcurrentHashMap<>();

        @Override
        public void add(LogEntry entry) {
            map.computeIfAbsent(entry.path(), k -> new UrlStats()).add(entry);
        }

        @Override
        public Map<String, PathStatistics> snapshot() {
            Map<String, PathStatistics> result = new HashMap<>();
            for (Map.Entry<String, UrlStats> e : map.entrySet()) {
                result.put(e.getKey(), e.getValue().snapshot());
            }
            return result;
        }
    }

    static StatsAccumulator newAccumulator(String kind) {
        if (kind.equals("global")) {
            return new GlobalLockAccumulator();
        }
        if (kind.equals("perurl")) {
            return new PerUrlAccumulator();
        }
        throw new IllegalArgumentException("Неизвестный режим: " + kind);
    }

    // 3, 5, 6, 7, 8, 9. Параллельный анализатор

    static final class Analyzer {
        private final int threads;
        private final int permits;
        private final Semaphore semaphore;
        private final StatsAccumulator stats;

        // флаг остановки
        private volatile boolean stopRequested;

        private final AtomicInteger processedFiles = new AtomicInteger();
        private final AtomicInteger stoppedFiles = new AtomicInteger();
        private final AtomicInteger activeFiles = new AtomicInteger();
        private final AtomicInteger maxActiveFiles = new AtomicInteger();
        private final AtomicLong readLines = new AtomicLong();
        private final AtomicLong validEntries = new AtomicLong();
        private final AtomicLong corruptedLines = new AtomicLong();
        private final AtomicLong readErrors = new AtomicLong();
        private final List<String> failedNames =
                Collections.synchronizedList(new ArrayList<>());

        Analyzer(int threads, int permits, StatsAccumulator stats) {
            if (threads < 1 || permits < 1) {
                throw new IllegalArgumentException(
                        "threads и permits должны быть >= 1");
            }
            this.threads = threads;
            this.permits = permits;
            this.semaphore = new Semaphore(permits);
            this.stats = stats;
        }

        void stop() {
            stopRequested = true;
        }

        long linesRead() {
            return readLines.get();
        }

        Result run(List<LogFile> files) throws InterruptedException {
            ExecutorService pool = Executors.newFixedThreadPool(threads);
            CountDownLatch latch = new CountDownLatch(files.size());

            try {
                for (LogFile file : files) {
                    pool.execute(() -> {
                        try {
                            processFile(file);
                        } finally {
                            latch.countDown();
                        }
                    });
                }
                latch.await();
            } catch (InterruptedException e) {
                pool.shutdownNow();
                throw e;
            } finally {
                pool.shutdown();
            }

            if (!pool.awaitTermination(1, TimeUnit.MINUTES)) {
                pool.shutdownNow();
            }

            Map<String, PathStatistics> snapshot = stats.snapshot();
            return new Result(
                    buildReport(snapshot),
                    snapshot,
                    processedFiles.get(),
                    stoppedFiles.get(),
                    (int) readErrors.get(),
                    new ArrayList<>(failedNames),
                    readLines.get(),
                    validEntries.get(),
                    corruptedLines.get(),
                    maxActiveFiles.get(),
                    activeFiles.get(),
                    stopRequested
            );
        }

        private void processFile(LogFile file) {
            if (stopRequested) {
                stoppedFiles.incrementAndGet();
                return;
            }

            try {
                semaphore.acquire();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                stoppedFiles.incrementAndGet();
                return;
            }

            try {
                int now = activeFiles.incrementAndGet();
                updateMax(now);
                try {
                    readFile(file);
                } finally {
                    activeFiles.decrementAndGet();
                }
            } finally {
                semaphore.release();
            }
        }

        private void readFile(LogFile file) {
            try {
                Iterator<String> it = LogFileLines.iterator(file.path());
                while (it.hasNext()) {
                    if (stopRequested) {
                        stoppedFiles.incrementAndGet();
                        return;
                    }
                    String line = it.next();
                    readLines.incrementAndGet();
                    try {
                        LogEntry entry = parseLine(line);
                        stats.add(entry);
                        validEntries.incrementAndGet();
                    } catch (IllegalArgumentException e) {
                        corruptedLines.incrementAndGet();
                    }
                }
                processedFiles.incrementAndGet();
            } catch (RuntimeException e) {
                readErrors.incrementAndGet();
                failedNames.add(file.path().getFileName() + ": " + e.getMessage());
            }
        }

        private void updateMax(int now) {
            int old = maxActiveFiles.get();
            while (now > old && !maxActiveFiles.compareAndSet(old, now)) {
                old = maxActiveFiles.get();
            }
        }
    }

    static List<LogFile> listLogFiles(Path directory) throws IOException {
        try (var paths = Files.list(directory)) {
            return paths
                    .filter(p -> p.getFileName().toString().endsWith(".log"))
                    .sorted()
                    .map(LogFile::new)
                    .toList();
        }
    }

    static void printResult(Result r) {
        Report rep = r.report();
        System.out.println("Всего запросов:   " + rep.totalRequests());
        System.out.println("Успешных:         " + rep.successfulRequests());
        System.out.println("Ошибочных:        " + rep.errorRequests());
        System.out.println("Байт в ответах:   " + rep.responseBytes());
        System.out.println("Макс. время, мс:  " + rep.maxDurationMillis());
        System.out.println();
        System.out.println("Файлов обработано: " + r.processedFiles()
                + ", остановлено: " + r.stoppedFiles()
                + ", с ошибкой: " + r.failedFiles());
        System.out.println("Строк прочитано: " + r.readLines()
                + ", корректных: " + r.validEntries()
                + ", повреждённых: " + r.corruptedLines());
        System.out.println("Макс. одновременно активных файлов: "
                + r.maxActiveFiles());
        for (String name : r.failedNames()) {
            System.out.println("НЕ УДАЛОСЬ ОБРАБОТАТЬ: " + name);
        }
        if (r.stopRequested()) {
            System.out.println("Анализ был остановлен досрочно, отчёт частичный");
        }
        System.out.println();
        System.out.println("По URL:");
        for (Map.Entry<String, PathStatistics> e
                : new TreeMap<>(r.byPath()).entrySet()) {
            PathStatistics s = e.getValue();
            System.out.printf("  %-14s req=%d ok=%d err=%d bytes=%d total=%d max=%d%n",
                    e.getKey(), s.requests(), s.successful(), s.errors(),
                    s.responseBytes(), s.totalDurationMillis(),
                    s.maxDurationMillis());
        }
    }

    private static void selfCheck() throws IOException {
        Path directory = Files.createTempDirectory("log-assignment-");
        GenerateLogs.generate(directory, 3, 7);

        int files = 0;
        int lines = 0;

        try (var paths = Files.list(directory)) {
            for (Path path : paths.toList()) {
                files++;
                Iterator<String> iterator = LogFileLines.iterator(path);

                while (iterator.hasNext()) {
                    String line = iterator.next();
                    String[] fields = line.trim().split("\\s+");
                    if (fields.length != 5) {
                        throw new AssertionError(
                                "Unexpected line: " + line
                        );
                    }
                    Integer.parseInt(fields[2]);
                    Long.parseLong(fields[3]);
                    Long.parseLong(fields[4]);
                    lines++;
                }
            }
        }

        if (files != 3 || lines != 21) {
            throw new AssertionError(
                    "Expected 3 files and 21 lines, got "
                            + files + " files and " + lines + " lines"
            );
        }

        System.out.println(
                "OK: generated " + files
                        + " files and read " + lines + " lines"
        );
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void deleteDirectory(Path directory) throws IOException {
        for (Path file : Files.list(directory).toList()) {
            Files.delete(file);
        }
        Files.delete(directory);
    }

    private static void checkInvariants(Result r, int permitLimit, int fileCount) {
        for (PathStatistics s : r.byPath().values()) {
            require(s.requests() == s.successful() + s.errors(),
                    "requests != successful + errors");
            require(s.requests() == 0
                            || s.maxDurationMillis() <= s.totalDurationMillis(),
                    "max > total");
        }
        require(r.maxActiveFiles() <= permitLimit,
                "активных файлов больше лимита семафора");
        require(r.activeFilesAtEnd() == 0, "activeFiles != 0 в конце");
        require(r.processedFiles() + r.stoppedFiles() + r.failedFiles()
                        == fileCount,
                "не каждый файл учтён ровно один раз");
        require(r.readLines() == r.validEntries() + r.corruptedLines(),
                "прочитанные строки != корректные + повреждённые");
        require(r.report().totalRequests() == r.validEntries(),
                "в статистике не столько записей, сколько корректных строк");
    }

    private static void testParse() {
        LogEntry e = parseLine("GET /api/users 200 820 4");
        require(e.method().equals("GET") && e.path().equals("/api/users")
                && e.status() == 200 && e.responseBytes() == 820
                && e.durationMillis() == 4, "неверный разбор");

        LogEntry spaced = parseLine("  POST   /login  401   10    7  ");
        require(spaced.status() == 401 && spaced.durationMillis() == 7,
                "несколько пробелов");

        String[] bad = {
                "", "GET /a 200 10", "GET /a 200 10 5 6", "GET /a abc 10 5",
                "GET /a 200 x 5", "GET /a 200 10 y", "GET /a 700 10 5",
                "GET /a 200 -1 5", "GET /a 100 10 5"
        };
        for (String line : bad) {
            try {
                parseLine(line);
                throw new AssertionError("Строка должна быть отклонена: " + line);
            } catch (IllegalArgumentException expected) {
                // ошибка ожидалась
            }
        }
        System.out.println("OK: разбор строки");
    }

    private static void testParallelEqualsSequential() throws Exception {
        Path dir = Files.createTempDirectory("log-par-");
        GenerateLogs.generate(dir, 6, 500);
        List<LogFile> files = listLogFiles(dir);

        Result seq = analyzeSequential(files);
        require(seq.readLines() == 3000 && seq.validEntries() == 3000,
                "эталон прочитал не все строки");

        String[] kinds = {"global", "perurl"};
        int[][] configs = {{1, 1}, {4, 1}, {4, 4}, {8, 2}};
        for (String kind : kinds) {
            for (int[] c : configs) {
                Result par = new Analyzer(c[0], c[1], newAccumulator(kind))
                        .run(files);
                checkInvariants(par, c[1], files.size());
                require(par.byPath().equals(seq.byPath()),
                        "параллельный результат отличается от эталона ("
                                + kind + ", потоков " + c[0]
                                + ", разрешений " + c[1] + ")");
                require(par.report().equals(seq.report()),
                        "итоговый Report отличается");
                require(par.readLines() == 3000, "строки прочитаны не один раз");
            }
        }
        deleteDirectory(dir);
        System.out.println("OK: параллельный результат совпадает с эталоном");
    }

    private static void testSemaphoreLimit() throws Exception {
        Path dir = Files.createTempDirectory("log-sem-");
        GenerateLogs.generate(dir, 12, 20_000);
        List<LogFile> files = listLogFiles(dir);

        Result one = new Analyzer(6, 1, new PerUrlAccumulator()).run(files);
        require(one.maxActiveFiles() == 1, "при лимите 1 было активных: "
                + one.maxActiveFiles());
        checkInvariants(one, 1, files.size());

        Result two = new Analyzer(6, 2, new PerUrlAccumulator()).run(files);
        require(two.maxActiveFiles() <= 2, "при лимите 2 было активных: "
                + two.maxActiveFiles());
        checkInvariants(two, 2, files.size());

        deleteDirectory(dir);
        System.out.println("OK: семафор (макс. активных при лимите 2: "
                + two.maxActiveFiles() + ")");
    }

    private static void testBrokenInput() throws Exception {
        Path dir = Files.createTempDirectory("log-broken-");
        GenerateLogs.generate(dir, 3, 100);

        Path first = dir.resolve("access-000.log");
        Files.writeString(first, "this is not a log line\n",
                StandardOpenOption.APPEND);

        Path badFile = dir.resolve("access-100.log");
        Files.write(badFile, new byte[]{(byte) 0xff, (byte) 0xfe, '\n'});

        List<LogFile> goodOnly = listLogFiles(dir).stream()
                .filter(f -> !f.path().equals(badFile)).toList();
        List<LogFile> all = new ArrayList<>(goodOnly);
        all.add(new LogFile(badFile));
        // и файл, которого просто нет
        all.add(new LogFile(dir.resolve("missing.log")));

        Result reference = analyzeSequential(goodOnly);
        Result r = new Analyzer(4, 2, new PerUrlAccumulator()).run(all);

        require(r.corruptedLines() == 1, "повреждённых строк: "
                + r.corruptedLines());
        require(r.failedFiles() == 2, "файлов с ошибкой: " + r.failedFiles());
        require(r.processedFiles() == 3, "обработано файлов: "
                + r.processedFiles());
        require(r.byPath().equals(reference.byPath()),
                "ошибки в файлах повлияли на остальные данные");
        checkInvariants(r, 2, all.size());

        deleteDirectory(dir);
        System.out.println("OK: повреждённая строка и повреждённые файлы "
                + "(ошибки: " + r.failedNames().size() + ")");
    }

    private static void testStop() throws Exception {
        Path dir = Files.createTempDirectory("log-stop-");
        GenerateLogs.generate(dir, 8, 100_000);
        List<LogFile> files = listLogFiles(dir);

        // остановка до запуска
        Analyzer early = new Analyzer(4, 2, new PerUrlAccumulator());
        early.stop();
        Result r0 = early.run(files);
        require(r0.stoppedFiles() == files.size() && r0.readLines() == 0,
                "после stop() до запуска ничего не должно читаться");
        checkInvariants(r0, 2, files.size());

        // остановка во время работы
        Analyzer analyzer = new Analyzer(4, 2, new PerUrlAccumulator());
        Thread watcher = new Thread(() -> {
            while (analyzer.linesRead() < 1000) {
                Thread.yield();
            }
            analyzer.stop();
        });
        watcher.start();
        Result r = analyzer.run(files);
        watcher.join();

        require(r.stopRequested(), "флаг остановки не виден в результате");
        require(r.stoppedFiles() > 0, "ни один файл не остановлен");
        require(r.readLines() < 800_000, "остановка не сработала");
        checkInvariants(r, 2, files.size());

        deleteDirectory(dir);
        System.out.println("OK: досрочная остановка (прочитано "
                + r.readLines() + " строк из 800000, остановлено файлов: "
                + r.stoppedFiles() + ")");
    }

    private static void runTests() throws Exception {
        testParse();
        testParallelEqualsSequential();
        testSemaphoreLimit();
        testBrokenInput();
        testStop();
        System.out.println("Все проверки пройдены");
    }

    // Эксперименты
    private static void writeLogs(Path dir, int files, int lines,
                                  int urlCount, double hotShare)
            throws IOException {
        Files.createDirectories(dir);
        Random random = new Random(1);
        for (int f = 0; f < files; f++) {
            Path file = dir.resolve("access-%03d.log".formatted(f));
            try (BufferedWriter w = Files.newBufferedWriter(file,
                    StandardCharsets.UTF_8)) {
                for (int i = 0; i < lines; i++) {
                    String path = random.nextDouble() < hotShare
                            ? "/hot"
                            : "/url-" + random.nextInt(urlCount);
                    int status = random.nextInt(10) < 8 ? 200 : 500;
                    w.write("GET " + path + " " + status + " "
                            + (100 + random.nextInt(5000)) + " "
                            + (1 + random.nextInt(300)) + "\n");
                }
            }
        }
    }

    private static long measure(Callable<Result> task) throws Exception {
        task.call();
        long sum = 0;
        for (int i = 0; i < 3; i++) {
            long start = System.nanoTime();
            task.call();
            sum += (System.nanoTime() - start) / 1_000_000;
        }
        return sum / 3;
    }

    private static void runExperiments() throws Exception {
        Path hotDir = Files.createTempDirectory("log-hot-");
        Path manyDir = Files.createTempDirectory("log-many-");
        writeLogs(hotDir, 16, 100_000, 5, 0.99);
        writeLogs(manyDir, 16, 100_000, 20_000, 0.0);
        List<LogFile> hot = listLogFiles(hotDir);
        List<LogFile> many = listLogFiles(manyDir);

        System.out.println("Данные: 16 файлов по 100000 строк. "
                + "Ядер процессора: "
                + Runtime.getRuntime().availableProcessors());
        System.out.println("Время - среднее из 3 запусков, мс.");
        System.out.println();

        System.out.println("1) Число рабочих потоков (permits=4, perurl, много URL)");
        for (int t : new int[]{1, 4}) {
            long ms = measure(() ->
                    new Analyzer(t, 4, new PerUrlAccumulator()).run(many));
            System.out.println("   потоков " + t + ": " + ms + " мс");
        }

        System.out.println("2) Лимит семафора (4 потока, perurl, много URL)");
        for (int p : new int[]{1, 4}) {
            long ms = measure(() ->
                    new Analyzer(4, p, new PerUrlAccumulator()).run(many));
            System.out.println("   разрешений " + p + ": " + ms + " мс");
        }

        System.out.println("3) Глобальный замок и замки по URL (4 потока, permits=4)");
        String[] kinds = {"global", "perurl"};
        for (String kind : kinds) {
            long hotMs = measure(() ->
                    new Analyzer(4, 4, newAccumulator(kind)).run(hot));
            long manyMs = measure(() ->
                    new Analyzer(4, 4, newAccumulator(kind)).run(many));
            System.out.println("   " + kind + ": один URL " + hotMs
                    + " мс, много URL " + manyMs + " мс");
        }
        long seqMs = measure(() -> analyzeSequential(many));
        System.out.println("   (для сравнения последовательно, много URL: "
                + seqMs + " мс)");

        System.out.println("4) Повреждённые данные");
        Path first = hotDir.resolve("access-000.log");
        Files.writeString(first, "broken line here\n", StandardOpenOption.APPEND);
        Files.write(hotDir.resolve("access-999.log"),
                new byte[]{(byte) 0xff, (byte) 0xfe, '\n'});
        Result r = new Analyzer(4, 4, new PerUrlAccumulator())
                .run(listLogFiles(hotDir));
        System.out.println("   запросов в отчёте: " + r.report().totalRequests()
                + " (ожидалось 1600000), повреждённых строк: "
                + r.corruptedLines() + ", файлов с ошибкой: "
                + r.failedFiles() + " " + r.failedNames());

        deleteDirectory(hotDir);
        deleteDirectory(manyDir);
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("generate")) {
            Path directory = Path.of(
                    args.length > 1 ? args[1] : "logs"
            );
            int fileCount = args.length > 2
                    ? Integer.parseInt(args[2])
                    : 20;
            int linesPerFile = args.length > 3
                    ? Integer.parseInt(args[3])
                    : 1_000;

            GenerateLogs.generate(
                    directory,
                    fileCount,
                    linesPerFile
            );

            System.out.println(
                    "Generated " + fileCount
                            + " files in " + directory
            );
            return;
        }

        if (args.length > 0 && args[0].equals("check")) {
            selfCheck();
            return;
        }

        if (args.length > 0 && args[0].equals("test")) {
            runTests();
            return;
        }

        if (args.length > 0 && args[0].equals("experiments")) {
            runExperiments();
            return;
        }

        if (args.length > 1 && args[0].equals("seq")) {
            printResult(analyzeSequential(listLogFiles(Path.of(args[1]))));
            return;
        }

        if (args.length > 1 && args[0].equals("analyze")) {
            Path directory = Path.of(args[1]);
            int threads = args.length > 2 ? Integer.parseInt(args[2]) : 4;
            int permits = args.length > 3 ? Integer.parseInt(args[3]) : 4;
            String kind = args.length > 4 ? args[4] : "perurl";

            Analyzer analyzer = new Analyzer(threads, permits,
                    newAccumulator(kind));
            printResult(analyzer.run(listLogFiles(directory)));
            return;
        }

        System.out.println(
                "Usage: java LogAnalysisAssignment "
                        + "generate <directory> <files> <lines>"
        );
        System.out.println(
                "       java LogAnalysisAssignment check"
        );
        System.out.println(
                "       java LogAnalysisAssignment test"
        );
        System.out.println(
                "       java LogAnalysisAssignment seq <directory>"
        );
        System.out.println(
                "       java LogAnalysisAssignment analyze <directory> "
                        + "[threads] [permits] [global|perurl]"
        );
        System.out.println(
                "       java LogAnalysisAssignment experiments"
        );
    }
}