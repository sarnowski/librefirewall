use super::*;

const MINIMAL: &str = "{\n  \"arch\": \"x86_64\",\n  \"features\": \"-sse,+soft-float\"\n}\n";
const SIMD: &str = "{\n  \"arch\": \"x86_64\",\n  \"features\": \"+sse,+aes,-bmi2\"\n}\n";

/// A workspace whose `support/targets` holds the two specifications above, and a
/// separate directory to stand in for a `CARGO_TARGET_DIR`.
struct Bench {
    root: PathBuf,
    target_dir: PathBuf,
}

impl Bench {
    fn new(name: &str) -> Self {
        let root = scratch(name);
        let targets = root.join(DIRECTORY);
        fs::create_dir_all(&targets).unwrap();
        fs::write(targets.join("minimal.json"), MINIMAL).unwrap();
        fs::write(targets.join("simd.json"), SIMD).unwrap();
        let target_dir = root.join("target");
        Self { root, target_dir }
    }

    fn reconcile(&self, target: &str) -> Result<(), Error> {
        reconcile(&self.root, &self.target_dir, target)
    }

    /// Stand in for a compiled artifact, so a discard is observable.
    fn drop_artifact(&self, target: &str) {
        fs::write(
            self.target_dir.join(target).join("object.rlib"),
            b"compiled",
        )
        .unwrap();
    }

    fn artifact_survives(&self, target: &str) -> bool {
        self.target_dir.join(target).join("object.rlib").exists()
    }

    fn rewrite(&self, target: &str, text: &str) {
        fs::write(self.root.join(specification(target)), text).unwrap();
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).ok();
    }
}

#[test]
fn a_directory_nothing_has_built_yet_is_created_with_its_specification_recorded() {
    let bench = Bench::new("fresh");
    bench.reconcile("simd").unwrap();
    assert_eq!(
        fs::read_to_string(bench.target_dir.join("simd").join(RECORD)).unwrap(),
        SIMD
    );
}

#[test]
fn artifacts_compiled_against_the_specification_on_disk_are_reused() {
    let bench = Bench::new("warm");
    bench.reconcile("simd").unwrap();
    bench.drop_artifact("simd");
    bench.reconcile("simd").unwrap();
    assert!(
        bench.artifact_survives("simd"),
        "an unchanged specification must not cost a cold build"
    );
}

#[test]
fn a_changed_specification_discards_the_artifacts_compiled_against_the_old_one() {
    let bench = Bench::new("withdrawn");
    bench.reconcile("simd").unwrap();
    bench.drop_artifact("simd");

    // The withdrawal that broke a build: a feature the emulator refuses, taken
    // out of the specification while the objects using it stayed on disk.
    bench.rewrite("simd", &SIMD.replace("+aes,-bmi2", "+aes,-bmi,-bmi2"));
    bench.reconcile("simd").unwrap();

    assert!(
        !bench.artifact_survives("simd"),
        "an object compiled against the old specification must not be linked"
    );
    assert!(
        fs::read_to_string(bench.target_dir.join("simd").join(RECORD))
            .unwrap()
            .contains("-bmi,-bmi2"),
        "the new specification is what the next build is judged against"
    );
}

#[test]
fn a_specification_that_gains_a_feature_invalidates_just_as_one_that_loses_it_does() {
    // The direction nothing else catches: the binary would be quietly missing
    // the acceleration the edit was made to obtain.
    let bench = Bench::new("gained");
    bench.reconcile("simd").unwrap();
    bench.drop_artifact("simd");

    bench.rewrite("simd", &SIMD.replace("-bmi2", "+avx2"));
    bench.reconcile("simd").unwrap();

    assert!(!bench.artifact_survives("simd"));
}

#[test]
fn artifacts_that_record_no_specification_are_discarded() {
    // A directory built before any record was kept: nothing says what it was
    // compiled against, so nothing may be reused out of it.
    let bench = Bench::new("unrecorded");
    fs::create_dir_all(bench.target_dir.join("simd")).unwrap();
    bench.drop_artifact("simd");

    bench.reconcile("simd").unwrap();

    assert!(!bench.artifact_survives("simd"));
    assert!(bench.target_dir.join("simd").join(RECORD).exists());
}

#[test]
fn only_the_target_whose_specification_moved_loses_its_artifacts() {
    let bench = Bench::new("neighbour");
    bench.reconcile("minimal").unwrap();
    bench.reconcile("simd").unwrap();
    bench.drop_artifact("minimal");
    bench.drop_artifact("simd");

    bench.rewrite("simd", &SIMD.replace("+aes", "+aes,+pclmulqdq"));
    bench.reconcile("minimal").unwrap();
    bench.reconcile("simd").unwrap();

    assert!(
        bench.artifact_survives("minimal"),
        "one target's specification decides only that target's artifacts"
    );
    assert!(!bench.artifact_survives("simd"));
}

#[test]
fn a_sibling_of_the_target_directories_is_never_touched() {
    // The debug configuration builds into the same directory the host dev
    // profile writes to, so a discard that reached wider than one target would
    // throw away the host artifacts of every other command.
    let bench = Bench::new("sibling");
    bench.reconcile("simd").unwrap();
    let host = bench.target_dir.join("release");
    fs::create_dir_all(&host).unwrap();
    fs::write(host.join("build-script"), b"host").unwrap();

    bench.rewrite("simd", &SIMD.replace("+aes", "-aes"));
    bench.reconcile("simd").unwrap();

    assert!(host.join("build-script").exists());
}

#[test]
fn a_missing_specification_is_reported_with_the_path_it_looked_for() {
    let bench = Bench::new("absent");
    let error = bench.reconcile("no-such-target").unwrap_err().to_string();
    assert!(error.contains("read the target specification"), "{error}");
    assert!(error.contains("no-such-target.json"), "{error}");
}

#[test]
fn the_discard_names_the_lines_that_moved_in_both_directions() {
    let rendered = changed_lines(SIMD, &SIMD.replace("-bmi2", "+bmi2"));
    assert!(
        rendered.contains("- was: \"features\": \"+sse,+aes,-bmi2\""),
        "{rendered}"
    );
    assert!(
        rendered.contains("+ now: \"features\": \"+sse,+aes,+bmi2\""),
        "{rendered}"
    );
    assert!(
        !rendered.contains("arch"),
        "an unchanged line is noise in a diff: {rendered}"
    );
}

#[test]
fn a_reordering_renders_nothing_rather_than_an_empty_claim() {
    let reordered = "{\n  \"features\": \"+sse,+aes,-bmi2\"\n  \"arch\": \"x86_64\",\n}\n";
    assert_eq!(changed_lines(SIMD, reordered), "");
}

fn scratch(name: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "librefirewall-target-spec-{name}-{}-{unique}",
        std::process::id()
    ))
}
