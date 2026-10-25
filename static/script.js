// ======================================================
// CLOUDGUARD JAVASCRIPT
// ======================================================


// ======================================================
// RUN SECURITY SCAN
// ======================================================

const scanButton =
    document.querySelector(".scan-btn");


if (scanButton) {

    scanButton.addEventListener(
        "click",
        async function () {

            scanButton.disabled = true;

            scanButton.innerHTML =
                "⏳ Scanning...";

            try {

                const response =
                    await fetch(
                        "/api/scan",
                        {
                            method: "POST"
                        }
                    );

                const data =
                    await response.json();


                if (data.success) {

                    scanButton.innerHTML =
                        "✅ Scan Complete";


                    setTimeout(
                        function () {

                            location.reload();

                        },
                        700
                    );

                }

            } catch (error) {

                console.error(
                    "Scan error:",
                    error
                );

                scanButton.innerHTML =
                    "❌ Scan Failed";

                scanButton.disabled = false;

            }

        }
    );

}


// ======================================================
// LOAD DASHBOARD DATA
// ======================================================

async function loadDashboardData() {

    try {

        const response =
            await fetch(
                "/api/dashboard-data"
            );


        if (!response.ok) {

            throw new Error(
                "Failed to load dashboard data"
            );

        }


        const data =
            await response.json();


        console.log(
            "CloudGuard data:",
            data
        );


        createSeverityChart(data);

        createResourceChart(data);

        setupFindingDetails(data);


    } catch (error) {

        console.error(
            "Dashboard error:",
            error
        );

    }

}


// ======================================================
// SEVERITY CHART
// ======================================================

function createSeverityChart(data) {

    const canvas =
        document.getElementById(
            "severityChart"
        );


    if (!canvas) {

        return;

    }


    if (typeof Chart === "undefined") {

        console.error(
            "Chart.js is not loaded."
        );

        return;

    }


    new Chart(
        canvas,
        {

            type: "doughnut",

            data: {

                labels: [
                    "Critical",
                    "High",
                    "Medium",
                    "Low"
                ],

                datasets: [

                    {

                        data: [

                            data.critical,
                            data.high,
                            data.medium,
                            data.low

                        ],

                        backgroundColor: [

                            "#38a3e0",
                            "#ff5f7e",
                            "#ff9f40",
                            "#ffd05a"

                        ],

                        borderColor:
                            "#0d1524",

                        borderWidth: 3

                    }

                ]

            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                plugins: {

                    legend: {

                        position: "bottom",

                        labels: {

                            color: "#c2cad7",

                            padding: 15

                        }

                    }

                }

            }

        }
    );

}


// ======================================================
// RESOURCE SECURITY CHART
// ======================================================

function createResourceChart(data) {

    const canvas =
        document.getElementById(
            "resourceChart"
        );


    if (!canvas) {

        return;

    }


    if (typeof Chart === "undefined") {

        console.error(
            "Chart.js is not loaded."
        );

        return;

    }


    new Chart(
        canvas,
        {

            type: "doughnut",

            data: {

                labels: [
                    "Secure",
                    "At Risk"
                ],

                datasets: [

                    {

                        data: [

                            data.secure_resources,
                            data.risky_resources

                        ],

                        backgroundColor: [

                            "#4ade80",
                            "#ef4444"

                        ],

                        borderColor:
                            "#0d1524",

                        borderWidth: 3

                    }

                ]

            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                plugins: {

                    legend: {

                        position: "bottom",

                        labels: {

                            color: "#c2cad7",

                            padding: 15

                        }

                    }

                }

            }

        }
    );

}


// ======================================================
// FINDING DETAILS
// ======================================================

function setupFindingDetails(data) {

    const buttons =
        document.querySelectorAll(
            ".details-btn"
        );


    buttons.forEach(
        function (button) {

            button.addEventListener(
                "click",
                function () {

                    const index =
                        Number(
                            button.dataset.findingIndex
                        );


                    const finding =
                        data.findings[index];


                    if (finding) {

                        showFindingDetails(
                            finding
                        );

                    }

                }
            );

        }
    );

}


// ======================================================
// SHOW FINDING DETAILS
// ======================================================

function showFindingDetails(
    finding
) {

    const issue =
        document.getElementById(
            "modalIssue"
        );


    const resource =
        document.getElementById(
            "modalResource"
        );


    const severity =
        document.getElementById(
            "modalSeverity"
        );


    const description =
        document.getElementById(
            "modalDescription"
        );


    const recommendation =
        document.getElementById(
            "modalRecommendation"
        );


    if (issue) {

        issue.textContent =
            finding.issue;

    }


    if (resource) {

        resource.textContent =
            finding.resource;

    }


    if (severity) {

        severity.textContent =
            finding.severity;

        severity.className =
            "modal-severity-badge " +
            finding.severity.toLowerCase();

    }


    if (description) {

        description.textContent =
            finding.description;

    }


    if (recommendation) {

        recommendation.textContent =
            finding.recommendation;

    }


    const modal =
        document.getElementById(
            "findingModal"
        );


    if (modal) {

        modal.classList.add(
            "show"
        );

    }

}


// ======================================================
// CLOSE FINDING DETAILS
// ======================================================

function closeFindingDetails() {

    const modal =
        document.getElementById(
            "findingModal"
        );


    if (modal) {

        modal.classList.remove(
            "show"
        );

    }

}


// ======================================================
// CLOSE MODAL OUTSIDE CLICK
// ======================================================

window.addEventListener(
    "click",
    function (event) {

        const modal =
            document.getElementById(
                "findingModal"
            );


        if (
            modal &&
            event.target === modal
        ) {

            closeFindingDetails();

        }

    }
);


// ======================================================
// START CLOUDGUARD
// ======================================================

loadDashboardData();