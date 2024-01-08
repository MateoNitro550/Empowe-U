document.addEventListener('DOMContentLoaded', function () {
    fetch('/get_total_count_data')
        .then(response => response.json())
        .then(data => {
            createChart(data.labels_mapped, data.labels_original, data.values);
        });
});

function createChart(labelsMapped, labelsOriginal, values) {
    var chartContainer = document.getElementById('chart-container');

    var trace1 = {
        labels: labelsMapped,
        customdata: labelsOriginal,
        values: values,
        type: 'pie',
        hole: 0.4,
        hoverinfo: 'label+percent+value+name',
        hovertemplate: 'Category: %{label}<br>Count: %{value}<br>Percentage: %{percent}',
        textinfo: 'label+percent+value',
        insidetextorientation: 'horizontal',
        textposition: 'inside',
        name: '',
    };

    var data = [trace1];

    var layout = {
        showlegend: true,
        legend: {
            title: 'Categories',
            orientation: 'v',
            yanchor: 'top',
            y: 1,
            xanchor: 'left',
            x: 1,
            font: { size: 20 },
        },
        margin: { l: 0, r: 0, b: 0, t: 0 },
        height: 800,
        width: 800,
        font: { size: 20 },
    };

    var config = {
      displayModeBar: false,
    };

    Plotly.newPlot(chartContainer, data, layout, config);

    chartContainer.on('plotly_click', data => window.location.href = '/segmentation/' + data.points[0].customdata);
}
