# Guide to Incremental Java Development

## Introduction

This guide will help you (as an AI assistant) work effectively with humans to incrementally develop and refactor Java code using JetBrains IDE tools. Following these practices will help you make precise, controlled edits rather than large, sweeping changes that can be difficult to review and implement.

## Core Principles

1. **Small, Targeted Changes**: Break down large development tasks into smaller, manageable steps
2. **Step-by-Step Methodology**: Implement a systematic approach to code changes
3. **Context Maintenance**: Keep track of the necessary context for each change
4. **Verification**: Regularly verify changes work as expected

## Using JetBrains MCP Tools Efficiently

The JetBrains MCP (Multi-Client Protocol) tools work best when making targeted edits rather than generating entire files at once. You should leverage these tools to make precise modifications to the codebase.

## Practical Implementation Strategies

### Editing Files

Use the `replace_specific_text` function to make targeted edits:

<targeted edit example>
// Example: Adding a new method to an existing class
await replace_specific_text({
  pathInProject: "src/main/java/com/example/service/UserService.java",
  oldText: "} // End of class",
  newText: "    /**\n     * Get user by email\n     * @param email user email\n     * @return optional user\n     */\n    public Optional<User> findByEmail(String email) {\n        return userRepository.findByEmail(email);\n    }\n} // End of class"
});
</targeted edit example>

### Creating Files

Create a skeleton first, then incrementally add functionality:

<create file example>
// Step 1: Create the file with basic structure
await create_new_file_with_text({
  pathInProject: "src/main/java/com/example/service/PaymentService.java",
  text: "package com.example.service;\n\nimport com.example.model.Payment;\n\n/**\n * Service for processing payments\n */\npublic class PaymentService {\n    // TODO: Implement methods\n}"
});

// Step 2: Add fields and constructor
await replace_specific_text({
  pathInProject: "src/main/java/com/example/service/PaymentService.java",
  oldText: "    // TODO: Implement methods",
  newText: "    private final PaymentRepository repository;\n    \n    public PaymentService(PaymentRepository repository) {\n        this.repository = repository;\n    }"
});

// Step 3: Add methods one at a time
</create file example>

### Key JetBrains Tools for Incremental Development

<incremental development example>
// 1. Getting file content
const fileContent = await get_file_text_by_path({
  pathInProject: "src/main/java/com/example/MyClass.java"
});

// 2. Replacing specific text (preferred for small changes)
const result = await replace_specific_text({
  pathInProject: "src/main/java/com/example/MyClass.java",
  oldText: "private void oldMethod() {\n  // Old implementation\n}",
  newText: "private void refactoredMethod() {\n  // New implementation\n}"
});

// 3. Creating a new file (when needed)
const createResult = await create_new_file_with_text({
  pathInProject: "src/main/java/com/example/NewClass.java",
  text: "package com.example;\n\npublic class NewClass {\n  // Implementation\n}"
});

// 4. Finding files (when you need to locate related files)
const files = await find_files_by_name_substring({
  nameSubstring: "Service"
});

// 5. Targeted whole file replacement (use sparingly)
const replaceResult = await replace_file_text_by_path({
  pathInProject: "src/main/java/com/example/SimpleClass.java",
  text: "// New file content here"
});
</incremental development example>

## Exploring Code Before Modification

Before making changes to code, always explore the existing codebase to understand its structure and context:

<exploration example>
// 1. First, find relevant files
const serviceFiles = await find_files_by_name_substring({
  nameSubstring: "Service"
});
console.log("Found service files:", serviceFiles);

// 2. Examine the specific file you'll be modifying
const userServiceContent = await get_file_text_by_path({
pathInProject: "src/main/java/com/example/service/UserService.java"
});
console.log("Current UserService implementation:", userServiceContent);

// 3. Look for related entity classes
const userEntityContent = await get_file_text_by_path({
pathInProject: "src/main/java/com/example/model/User.java"
});
console.log("User entity definition:", userEntityContent);

// 4. Check for repository interfaces
const repoContent = await get_file_text_by_path({
pathInProject: "src/main/java/com/example/repository/UserRepository.java"
});
console.log("UserRepository interface:", repoContent);
</exploration example>

Always explore code before modifying it to ensure your changes are contextually appropriate and maintain consistency with existing patterns. This helps avoid introducing bugs or breaking existing functionality.

## Incremental Development Approach

When developing or refactoring large Java files, follow this structured approach:

1. **Setup Skeleton**: Create the basic class structure with package, imports, class definition
2. **Add Core Fields/Methods**: Implement essential members and methods
3. **Expand Functionality**: Add more complex methods one at a time
4. **Refine Implementation**: Enhance existing methods with additional features
5. **Optimize**: Refactor for performance or readability

## Incremental Class Development

When developing a new class it should always take an incremental approach with each step utilizing a targeted edit.
Never create an entire class with a single call to `create_new_file_with_text`.

### Example: Building a Data Service Class
Here is an example approach of how to create a new class.

<example approach>
#### Step 1: Create Basic Class Structure

<create basic class structure example>
// First, create a new file with basic class structure
await create_new_file_with_text({
  pathInProject: "src/com/example/service/UserDataService.java",
  text: `package com.example.service;
import java.util.List;
import java.util.Optional;
/**
 * Service for managing user data
 */
public class UserDataService {
    // Will implement methods here
}
`
});
</create basic class structure example>

#### Step 2: Add Fields and Constructor

<add fields and constructor example>
// Add fields and constructor to the existing class
await replace_specific_text({
  pathInProject: "src/com/example/service/UserDataService.java",
  oldText: `import java.util.List;
import java.util.Optional;`,
  newText: `import java.util.List;
import java.util.Optional;
import com.example.repository.UserRepository;`
});

// Add constructor and fields
await replace_specific_text({
pathInProject: "src/com/example/service/UserDataService.java",
oldText: `public class UserDataService {
    // Will implement methods here
}`,
newText: `public class UserDataService {
private final UserRepository userRepository;

    public UserDataService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
}`
});
</add fields and constructor example>

#### Step 3: Add Core Method

<add core method example>
// Add import for User model
await replace_specific_text({
pathInProject: "src/com/example/service/UserDataService.java",
oldText: `import java.util.List;
import java.util.Optional;
import com.example.repository.UserRepository;`,
newText: `import java.util.List;
import java.util.Optional;
import com.example.repository.UserRepository;
import com.example.model.User;`
});

// Add core method
await replace_specific_text({
pathInProject: "src/com/example/service/UserDataService.java",
oldText: `public UserDataService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }`,
newText: `public UserDataService(UserRepository userRepository) {
this.userRepository = userRepository;
}

    /**
     * Find user by ID
     * @param id user identifier
     * @return optional containing user if found
     */
    public Optional<User> findUserById(Long id) {
        return userRepository.findById(id);
    }`
});
</add core method example>

#### Step 4: Add Additional Methods

<add additional methods example>
// Add method to find users by department
await replace_specific_text({
pathInProject: "src/com/example/service/UserDataService.java",
oldText: `public Optional<User> findUserById(Long id) {
        return userRepository.findById(id);
    }`,
newText: `public Optional<User> findUserById(Long id) {
return userRepository.findById(id);
}

    /**
     * Find users by department
     * @param department department name
     * @return list of users in the department
     */
    public List<User> findUsersByDepartment(String department) {
        return userRepository.findByDepartment(department);
    }`
});
</add additional methods example>

#### Step 5: Add Complex Business Logic

<add complex business logic example>
// Add method to transfer user between departments
await replace_specific_text({
pathInProject: "src/com/example/service/UserDataService.java",
oldText: `public List<User> findUsersByDepartment(String department) {
        return userRepository.findByDepartment(department);
    }`,
newText: `public List<User> findUsersByDepartment(String department) {
return userRepository.findByDepartment(department);
}

    /**
     * Transfer user between departments
     * @param userId user identifier
     * @param fromDepartment source department
     * @param toDepartment target department
     * @return true if transfer successful
     */
    public boolean transferUserDepartment(Long userId, String fromDepartment, String toDepartment) {
        Optional<User> userOpt = findUserById(userId);
        
        if (userOpt.isEmpty()) {
            return false;
        }
        
        User user = userOpt.get();
        if (!user.getDepartment().equals(fromDepartment)) {
            return false;
        }
        
        user.setDepartment(toDepartment);
        userRepository.save(user);
        return true;
    }`
});
</add complex business logic example>
</example approach>

## Effective Communication Patterns

When working on incremental Java development, use these structured communication patterns:

### 1. Ask for Clear Task Description

If the human hasn't provided a clear task, you can ask for it in this format:

<task_clarification>
  Could you please clarify what specific Java class you'd like me to create or modify? I'll need details about:
  - The class purpose and functionality
  - Any specific methods to implement
  - Related classes it should interact with
</task_clarification>

### 2. Acknowledge the File Context

When you understand the context, acknowledge it:

<file_context>
  I'll be working with:
  - Location: src/main/java/com/example/hr/LeaveRequestService.java
  - Related files:
    - src/main/java/com/example/hr/LeaveRequest.java (entity class)
    - src/main/java/com/example/hr/LeaveRequestRepository.java (repository interface)
</file_context>

### 3. Summarize Current Implementation

Before making changes, summarize what you understand about the current code:

<current_implementation>
I see the current LeaveRequestService class has:
- A repository dependency injected via constructor
- No methods implemented yet for handling leave requests
- The class is in the com.example.hr package
</current_implementation>

### 4. Outline Your Next Increment

Before implementing a change, outline what you'll do:

<next_increment>
  I'll now add a method to submit a new leave request that:
  - Takes employee ID, start date, end date, and reason
  - Validates that the start date is before end date
  - Creates a new LeaveRequest with PENDING status
  - Saves it to the repository
  - Returns the created request with its assigned ID
</next_increment>

### 5. Share Implementation Details

As you implement the change, explain your approach:

<implementation>
  I'm implementing the submitLeaveRequest method with:
  - LocalDate parameters for date handling
  - Validation logic for date ranges
  - Exception handling for invalid inputs
  - Repository interaction to save the entity
</implementation>

## Verification and Testing

After each increment, verify your changes:

<verification>
  I've verified that:
  1. The method signature matches the specification
  2. All validation logic is implemented correctly
  3. Proper exception handling is in place
  4. The repository is used correctly for persistence
  5. All necessary imports are included
</verification>

## Best Practices for Complex Refactoring

1. **Start with Tests**: Review or discuss tests first to understand expectations
2. **Extract Patterns**: Identify repeating patterns before making widespread changes
3. **Preserve Behavior**: Ensure your refactoring maintains the original behavior
4. **Work Inside-Out**: Start with core components, then refactor dependent components
5. **Document Decisions**: Add comments explaining non-obvious design decisions

## Common Pitfalls to Avoid

1. **Overloading Context**: Don't try to modify too much code at once - focus on related components
2. **Assuming Missing Information**: Ask questions when requirements are unclear
3. **Skipping Verification**: Always verify each increment before proceeding to the next
4. **Missing Dependencies**: Consider related classes that impact the current task
5. **Ignoring Standards**: Maintain consistent coding standards throughout development

## Advanced: Handling Larger Refactorings

For extensive refactorings, use a phased approach:

1. **Discovery Phase**: Analyze the existing code structure and dependencies
2. **Planning Phase**: Outline the specific changes needed across multiple files
3. **Implementation Phase**: Execute changes in small, ordered increments
4. **Verification Phase**: Test the changes to ensure functionality is preserved


## Conclusion
By taking an incremental approach to Java development and refactoring, you can produce high-quality code changes that
are easier to review and implement. Use the JetBrains MCP tools for targeted edits, communicate clearly about your
changes, and verify each step before proceeding to the next.