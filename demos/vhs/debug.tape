Output debug.gif
Set Width 1200
Set Height 800
Set Theme "Monokai Pro"
Set FontSize 18
Set Shell "bash"
Env TERM "xterm-256color"

# Build the basic example
Type "cd examples/basic && go build -o main main.go"
Enter
Sleep 2s

# Run the debug example
Type "./main"
Enter
Sleep 3s

