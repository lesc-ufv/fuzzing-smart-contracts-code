#code coverage
def code_coverage(logs):
    """ Track PCs hit during transaction for code coverage analysis. """
    covered_pcs = set()
    for log in logs:
        if "pc" in log:
            covered_pcs.add(log["pc"])
    return covered_pcs

def update_coverage(coverage_map, new_coverage):
    """ Update the coverage map with new transaction coverage """
    for pc in new_coverage:
        if pc not in coverage_map:
            coverage_map[pc] = 1
        else:
            coverage_map[pc] += 1
    return coverage_map

def calculate_coverage(coverage_map, total_pcs):
    """ Calculate percentage of code covered based on unique PCs """
    unique_pcs_covered = len(coverage_map.keys())
    coverage_percentage = (unique_pcs_covered / total_pcs) * 100
    print(f"Current Code Coverage: {coverage_percentage:.2f}%")
    return coverage_percentage
