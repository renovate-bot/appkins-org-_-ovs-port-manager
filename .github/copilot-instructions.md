Keep summaries concise, at most 2-3 sentences. Focus on the main points and avoid unnecessary details.
If you need to write temporary code for testing, please delete the file or add it to `.gitignore` after use.
Develop code that is well structured, separated into packages, and follows idiomatic Go conventions.
Packages should be single purpose and not contain unrelated code.
Do not polute the .git directory with unnecessary files. Add `.gitignore` entries to exclude files that should not be tracked.
Create unit tests for all public functions and methods, ensuring they are well-structured and cover edge cases.
Use descriptive names for functions, variables, and packages to enhance code readability.
Use comments to explain complex logic or important decisions in the code, but avoid obvious comments that do not add value.
Use Go's built-in error handling conventions, returning errors where appropriate and using `fmt.Errorf` for wrapping errors with context.
Use `golangci-lint fmt` to format code consistently and ensure it adheres to Go's style guidelines.
When writing documentation, use Go's standard documentation conventions, including package comments and function comments.
Use `go doc` to generate documentation from comments, ensuring it is clear and informative.
Use `go test` to run tests and ensure all tests pass before committing code.
Use `go mod tidy` to clean up the go.mod file, removing any unused dependencies.
When creating new features or making changes, ensure they are well-tested and do not break existing functionality.
Use version control best practices, including meaningful commit messages and branching strategies.