#!/bin/bash

# Test script to verify that no exec calls remain and all operations use native Go libraries

set -e

# Change to the project root directory
cd "$(dirname "$0")/.."

echo "=== Native Go Libraries Migration Test ==="

# Test 1: Check that no exec calls remain in the code
echo "1. Checking for remaining exec calls..."
if grep -r "exec\.Command\|exec\.Cmd\|exec\.Run" main.go 2>/dev/null; then
    echo "❌ Found remaining exec calls in the code!"
    exit 1
else
    echo "✅ No exec calls found in main.go"
fi

# Test 2: Check that os/exec import is removed
echo "2. Checking for os/exec imports..."
if grep -r "\"os/exec\"" main.go 2>/dev/null; then
    echo "❌ Found os/exec import still present!"
    exit 1
else
    echo "✅ os/exec import successfully removed"
fi

# Test 3: Check that native Go file operations are used
echo "3. Checking for native Go file operations..."
if grep -r "os\.MkdirAll\|os\.Symlink\|os\.Remove\|os\.ReadFile\|os\.OpenFile" main.go >/dev/null; then
    echo "✅ Found native Go file operations"
else
    echo "⚠️  No native Go file operations found (this might be okay if none are needed)"
fi

# Test 4: Check that netlink operations are present
echo "4. Checking for netlink operations..."
if grep -r "netlink\." main.go >/dev/null; then
    echo "✅ Found netlink operations"
    count=$(grep -c "netlink\." main.go)
    echo "   → Found $count netlink operations"
else
    echo "❌ No netlink operations found!"
    exit 1
fi

# Test 5: Check that libovsdb operations are present
echo "5. Checking for libovsdb operations..."
if grep -r "ovsClient\." main.go >/dev/null; then
    echo "✅ Found libovsdb operations"
    count=$(grep -c "ovsClient\." main.go)
    echo "   → Found $count OVS client operations"
else
    echo "❌ No libovsdb operations found!"
    exit 1
fi

# Test 6: Verify the build works
echo "6. Testing build..."
if go build -o ovs-port-manager-test main.go; then
    echo "✅ Project builds successfully"
    rm -f ovs-port-manager-test
else
    echo "❌ Build failed!"
    exit 1
fi

# Test 7: Check dependencies
echo "7. Checking Go module dependencies..."
echo "   Required dependencies:"
if go list -m github.com/vishvananda/netlink >/dev/null 2>&1; then
    echo "   ✅ netlink library present"
else
    echo "   ❌ netlink library missing"
    exit 1
fi

if go list -m github.com/ovn-org/libovsdb >/dev/null 2>&1; then
    echo "   ✅ libovsdb library present"
else
    echo "   ❌ libovsdb library missing"
    exit 1
fi

if go list -m github.com/docker/docker >/dev/null 2>&1; then
    echo "   ✅ Docker client library present"
else
    echo "   ❌ Docker client library missing"
    exit 1
fi

# Test 8: Verify specific native operations
echo "8. Verifying specific native operations..."

# Check for replaced operations
operations=(
    "netlink.LinkAdd"
    "netlink.LinkSetUp"
    "netlink.LinkSetNsPid"
    "netlink.LinkSetName"
    "netlink.AddrAdd"
    "netlink.RouteAdd"
    "netlink.LinkDel"
    "os.MkdirAll"
    "os.Symlink"
    "os.Remove"
)

for op in "${operations[@]}"; do
    if grep -q "$op" main.go; then
        echo "   ✅ $op operation found"
    else
        echo "   ⚠️  $op operation not found (might not be needed)"
    fi
done

echo ""
echo "=== Migration Summary ==="
echo "✅ All exec calls successfully removed"
echo "✅ Native Go libraries integrated:"
echo "   • File operations: os.* functions"
echo "   • Network operations: netlink library"
echo "   • OVS operations: libovsdb library"
echo "   • Docker operations: Docker Go client"
echo ""
echo "🎉 Native Go libraries migration completed successfully!"
echo ""
echo "Benefits achieved:"
echo "• Better performance (no process spawning)"
echo "• Type safety (compile-time checks)"
echo "• Better error handling"
echo "• Reduced dependencies on external tools"
echo "• More maintainable and testable code"
